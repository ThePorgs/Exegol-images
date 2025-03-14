#!/usr/bin/zsh

# Function to get config values from config.ini
function get_config_values() {
  HOST=$(awk -F '=' '/^host=/ {print $2}' /opt/tools/triliumnext/data/config.ini)
  PORT=$(awk -F '=' '/^port=/ {print $2}' /opt/tools/triliumnext/data/config.ini)

  if [[ -z "$PORT" ]]; then
    echo "Could not find port in config.ini"
    exit 1
  fi
}

# Function to start the application
function start_app() {
  get_config_values
  nvm use default
  nohup npm --prefix /opt/tools/triliumnext run server:start &> /tmp/triliumnext.nohup.out &
  # npx --prefix /opt/tools/triliumnext/ nodemon src/main.ts  # this command can be used instead of npm run server:start, especially if one needs to pass the TRILIUM_DATA_DIR env var
  NODE_PID=$!
  echo "Starting TriliumNext..."
  sleep 5
  if lsof -Pi :"$PORT" -sTCP:LISTEN -t >/dev/null ; then
    echo "TriliumNext is running on http://$HOST:$PORT"
  else
    echo "Application failed to start..."
    kill -9 "$NODE_PID" 2>/dev/null
    exit 2
  fi
}

# Function to test the application
function test_app() {
  get_config_values
  nvm use default
  nohup npm --prefix /opt/tools/triliumnext run server:start &> /dev/null &
  NODE_PID=$!
  sleep 5
  if lsof -Pi :"$PORT" -sTCP:LISTEN -t >/dev/null ; then
    echo "Trilium started successfully, stopping now..."
    kill -9 "$NODE_PID"
    exit 0
  else
    echo "Application failed to start..."
    kill -9 "$NODE_PID" 2>/dev/null
    exit 1
  fi
}

# Function to stop the application
function stop_app() {
  get_config_values
  if lsof -Pi :"$PORT" -s TCP:LISTEN -t >/dev/null ; then
    echo "TriliumNext is running on http://$HOST:$PORT, stopping now..."
    fuser -k "$PORT"/tcp
    sleep 2
    if lsof -Pi :"$PORT" -sTCP:LISTEN -t >/dev/null ; then
      echo "Something went wrong, TriliumNext still runs"
      exit 1
    else
      echo "TriliumNext stopped."
      exit 0
    fi
  else
    echo "Application is not running..."
    kill -9 "$NODE_PID" 2>/dev/null
    exit 0
  fi
}

# Function to configure the application
function configure_app() {
  get_config_values
  if lsof -Pi :"$PORT" -s TCP:LISTEN -t >/dev/null ; then
    echo "TriliumNext is running on http://$HOST:$PORT"
    curl --request POST "http://$HOST:$PORT/api/setup/new-document"
    curl --request POST --data-raw 'password1=exegol4thewin&password2=exegol4thewin' "http://$HOST:$PORT/set-password"
    exit 0
  else
    echo "Application is not running..."
    kill -9 "$NODE_PID" 2>/dev/null
    exit 1
  fi
}

# Load zsh settings
source /root/.zshrc
# Check script arguments
if [[ "$1" == "test" ]]; then
  test_app
elif [[ "$1" == "start" ]]; then
  start_app
elif [[ "$1" == "stop" ]]; then
  stop_app
elif [[ "$1" == "configure" ]]; then
  configure_app
else
  echo "Usage: $0 [test|start|stop|configure]"
  exit 1
fi
