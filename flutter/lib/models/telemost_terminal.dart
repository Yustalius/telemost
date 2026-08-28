import 'package:xterm/xterm.dart';

class TelemostTerminal extends Terminal {
  TelemostTerminal({super.maxLines});

  @override
  void eraseScrollbackOnly() {
    final scrollBack = buffer.scrollBack;
    if (scrollBack == 0) return;

    // Selection anchors require retained buffer lines to be reindexed.
    buffer.lines.remove(0, scrollBack);
  }
}
