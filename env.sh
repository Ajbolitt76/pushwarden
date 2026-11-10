# source this: toolchain for building the forks (installed in $HOME, no sudo)
export JAVA_HOME="$(ls -d $HOME/.local/opt/jdk-21* | head -1)"
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
