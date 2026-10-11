# Record with: vhs demo.tape
# Needs vhs and ttyd (pacman -S vhs), plus ffmpeg. Run it from the repo root.
#
# The recording replays testdata/demo.pcap, a minute of made-up traffic on a
# documentation network, so it needs no setcap and shows nothing about the
# machine it runs on. Regenerate the capture with: go run ./cmd/demopcap

Output demo.gif

Require go

Set Shell bash
Set FontSize 14
Set Width 1400
Set Height 820
Set Padding 20
Set Framerate 20
Set TypingSpeed 50ms
Set Theme "Catppuccin Mocha"

Hide
Type "export PS1='$ ' && go build -o ears . && clear"
Enter
Sleep 3s
Show

Type "./ears -r testdata/demo.pcap -speed 2"
Sleep 500ms
Enter

# Flows fill in as the replay runs.
Sleep 5s

Type "2"
Sleep 3s
Type "3"
Sleep 3s
Type "4"
Sleep 3s
Type "5"
Sleep 3500ms
Type "6"
Sleep 3s

# The map, then one device's details.
Type "7"
Sleep 2s
Down 2
Sleep 1s
Right
Sleep 1s
Enter
Sleep 3s
Escape
Sleep 1s

Type "q"
Sleep 500ms
