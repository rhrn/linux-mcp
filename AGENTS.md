I want secure linux mcp server via ssh

### Points
- implementation languange is Rust lang
- mcp server launched direct on server
- emulate ssh / shell / stream
- commands can be customizable via config

### Available commands (phase 1)
- ls
- pwd
- grep (and pipe)
- docker
    - ps
    - images
    - logs
    - inspect
    - events
    - history

### Examples
- ls -la
- docker ps | grep postgres
- docker logs -f {container}
