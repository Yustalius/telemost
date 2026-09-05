#!/usr/bin/env python3

import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
repo_root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('telemost_build', repo_root / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class MacOSFlutterBuildTest(unittest.TestCase):
    def setUp(self):
        self.original_cwd = Path.cwd()
        self.temp_dir = tempfile.TemporaryDirectory(prefix='telemost flutter build.')
        self.root = Path(self.temp_dir.name).resolve()
        self.flutter = self.root / 'flutter'
        self.config_path = self.flutter / '.dart_tool/package_config.json'
        self.config_path.parent.mkdir(parents=True)
        self.config = {
            'configVersion': 2,
            'packages': [
                {'name': 'flutter_hbb', 'rootUri': '../', 'packageUri': 'lib/',
                 'languageVersion': '3.1'},
            ],
            'generator': 'pub',
        }
        self.write_config()
        os.chdir(self.flutter)

    def tearDown(self):
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config), encoding='utf-8')

    def test_generated_package_mapping_preserves_pub_configuration(self):
        builder.prepare_macos_flutter_package_config()
        updated = json.loads(self.config_path.read_text(encoding='utf-8'))
        generated = updated['packages'].pop()
        self.assertEqual(updated, self.config)
        self.assertEqual(generated, {
            'name': 'telemost_build', 'rootUri': 'flutter_build/', 'packageUri': './',
        })
        self.assertNotIn(str(self.root), self.config_path.read_text(encoding='utf-8'))
        prepared = self.config_path.read_bytes()
        builder.prepare_macos_flutter_package_config()
        self.assertEqual(self.config_path.read_bytes(), prepared)

    def test_conflicting_package_is_not_overwritten(self):
        self.config['packages'].append({
            'name': 'telemost_build', 'rootUri': '../other/', 'packageUri': 'lib/',
        })
        self.write_config()
        original = self.config_path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'already in use'):
            builder.prepare_macos_flutter_package_config()
        self.assertEqual(self.config_path.read_bytes(), original)

    def test_mapping_invalidates_only_cached_kernel_stamps(self):
        build_dir = self.config_path.parent / 'flutter_build/cached-build'
        build_dir.mkdir(parents=True)
        kernel_stamp = build_dir / 'kernel_snapshot.stamp'
        other_stamp = build_dir / 'release_macos_bundle.stamp'
        kernel_stamp.write_text('cached kernel', encoding='utf-8')
        other_stamp.write_text('cached bundle', encoding='utf-8')
        builder.prepare_macos_flutter_package_config()
        self.assertFalse(kernel_stamp.exists())
        self.assertEqual(other_stamp.read_text(encoding='utf-8'), 'cached bundle')
        kernel_stamp.write_text('mapped kernel', encoding='utf-8')
        builder.prepare_macos_flutter_package_config()
        self.assertEqual(kernel_stamp.read_text(encoding='utf-8'), 'mapped kernel')

    def test_unknown_package_config_version_is_not_overwritten(self):
        self.config['configVersion'] = 3
        self.write_config()
        original = self.config_path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'version 2'):
            builder.prepare_macos_flutter_package_config()
        self.assertEqual(self.config_path.read_bytes(), original)

    def test_macos_build_keeps_mapping_architecture_and_external_symbols(self):
        for machine, arch, symbol_arch in (
            ('arm64', 'arm64', 'aarch64'), ('x86_64', 'x86_64', 'x86_64'),
        ):
            with self.subTest(machine=machine):
                commands = []

                def run(command):
                    commands.append(command)
                    if command == 'flutter pub get':
                        self.write_config()
                    if 'flutter build macos' in command:
                        config = json.loads(self.config_path.read_text(encoding='utf-8'))
                        self.assertEqual(config['packages'][-1]['name'], 'telemost_build')

                os.chdir(self.root)
                with mock.patch.object(builder, 'skip_cargo', True), \
                        mock.patch.object(builder, 'system2', run), \
                        mock.patch.object(builder.platform, 'machine', return_value=machine), \
                        mock.patch.object(builder.shutil, 'copy2'):
                    builder.build_flutter_dmg('1.5.0', 'flutter')
                build_command = next(c for c in commands if 'flutter build macos' in c)
                args = shlex.split(build_command)
                for arg in ('--no-pub', '--release', '--obfuscate',
                            'FLUTTER_XCODE_ARCHS=' + arch,
                            'FLUTTER_XCODE_ONLY_ACTIVE_ARCH=YES',
                            '--split-debug-info=../target/flutter-symbols/macos-' + symbol_arch):
                    self.assertIn(arg, args)
                service_command = next(c for c in commands if 'TelemostService' in c)
                signing_command = next(c for c in commands if 'macos-sign-adhoc.sh' in c)
                self.assertLess(commands.index('flutter pub get'), commands.index(build_command))
                self.assertLess(commands.index(build_command), commands.index(service_command))
                self.assertLess(commands.index(service_command), commands.index(signing_command))
                self.assertEqual(Path.cwd(), self.root)

    def test_adhoc_entitlements_allow_flutter_framework_loading(self):
        path = repo_root / 'flutter/macos/Runner/AdHocRelease.entitlements'
        with path.open('rb') as stream:
            entitlements = plistlib.load(stream)
        self.assertIs(entitlements['com.apple.security.cs.disable-library-validation'], True)
        self.assertIs(entitlements['com.apple.security.cs.allow-jit'], True)
        self.assertIs(entitlements['com.apple.security.app-sandbox'], False)

    @unittest.skipUnless(os.environ.get('TELEMOST_TEST_DART_SDK'), 'Dart SDK not selected for AOT smoke test')
    def test_aot_registrant_uri_and_runtime_routes(self):
        sdk = Path(os.environ['TELEMOST_TEST_DART_SDK'])
        tools_packages = os.environ['TELEMOST_TEST_FLUTTER_PACKAGES']
        registrant = self.flutter / '.dart_tool/flutter_build/dart_plugin_registrant.dart'
        registrant.parent.mkdir()
        registrant.write_text("@pragma('vm:entry-point')\nclass PluginRegistrant {}\n", encoding='utf-8')
        main = self.flutter / 'lib/main.dart'
        main.parent.mkdir()
        main.write_text("""
@pragma('vm:entry-point')
const String dartPluginRegistrantLibrary = String.fromEnvironment('flutter.dart_plugin_registrant');
void main(List<String> args) {
  final apiServer = args.single;
  print([apiServer, 'api', 'audit'].join('/'));
  print(dartPluginRegistrantLibrary);
}
""", encoding='utf-8')
        probe = self.root / 'package_uri.dart'
        probe.write_text("""
import 'dart:io';
import 'package:package_config/package_config.dart';
Future<void> main(List<String> args) async {
  final config = await loadPackageConfig(File(args[0]));
  final source = File(args[1]).absolute.uri;
  final uri = config.toPackageUri(source) ?? source;
  if (uri.scheme == 'package' && config.resolve(uri) != source) {
    throw StateError('Registrant URI does not resolve');
  }
  print(uri);
}
""", encoding='utf-8')

        def run(*args):
            try:
                return subprocess.check_output([str(arg) for arg in args], text=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as error:
                self.fail(error.output)

        def registrant_uri():
            return run(sdk / 'bin/dart', '--disable-dart-dev', '--packages=' + tools_packages,
                       probe, self.config_path, registrant).strip()

        def snapshot(name, uri):
            kernel = self.root / (name + '.dill')
            assembly = self.root / (name + '.S')
            library = self.root / (name + '.dylib')
            symbols = self.root / (name + '.symbols')
            run(sdk / 'bin/dartaotruntime', sdk / 'bin/snapshots/gen_kernel_aot.dart.snapshot',
                '--platform', sdk / 'lib/_internal/vm_platform_strong_product.dill',
                '--aot', '--packages', self.config_path, '--source', uri,
                '-Ddart.vm.product=true', '-Dflutter.dart_plugin_registrant=' + uri,
                '-o', kernel, 'package:flutter_hbb/main.dart')
            run(sdk / 'bin/utils/gen_snapshot', '--deterministic', '--obfuscate',
                '--dwarf-stack-traces', '--resolve-dwarf-paths',
                '--save-debugging-info=' + str(symbols), '--snapshot_kind=app-aot-assembly',
                '--assembly=' + str(assembly), kernel)
            run('/usr/bin/clang', '-dynamiclib', '-install_name', '@rpath/App.framework/App',
                assembly, '-o', library)
            run('/usr/bin/strip', '-x', library)
            self.assertGreater(symbols.stat().st_size, 0)
            return kernel, run('/usr/bin/strings', '-a', library)

        original_uri = registrant_uri()
        self.assertEqual(original_uri, registrant.as_uri())
        _, original_strings = snapshot('original', original_uri)
        self.assertTrue(original_uri in original_strings, 'Baseline must reproduce the workspace leak')
        builder.prepare_macos_flutter_package_config()
        mapped_uri = registrant_uri()
        self.assertEqual(mapped_uri, 'package:telemost_build/dart_plugin_registrant.dart')
        kernel, mapped_strings = snapshot('mapped', mapped_uri)
        for marker in (str(self.root), self.root.as_uri(), '/api/audit', '/api/heartbeat'):
            self.assertFalse(marker in mapped_strings, 'AOT still contains forbidden marker: ' + marker)
        self.assertTrue(mapped_uri in mapped_strings, 'Runtime registrant lookup URI must survive AOT')

        executable = self.root / 'mapped.aot'
        run(sdk / 'bin/utils/gen_snapshot', '--deterministic', '--obfuscate', '--strip',
            '--snapshot_kind=app-aot-elf', '--elf=' + str(executable), kernel)
        self.assertEqual(run(sdk / 'bin/dartaotruntime', executable, 'https://api.example.test'),
                         'https://api.example.test/api/audit\n' + mapped_uri + '\n')


if __name__ == '__main__':
    unittest.main()
