# [pwn.college](https://pwn.college/) Docker Setup

## On Host Machine
1. Build Custom Docker Image
> `docker image prune -f && docker build -t pwncollege_custom:v1 .`
- `docker image prune -f` forcefully removes unused images [optional]
- `-t` gives image a tag in 'name:tag' format
- `.` specifies location of [Dockerfile](./Dockerfile) is in current working directory

2. Run Docker Container
> `docker image prune -f && docker run -it --rm --name pwncollege_challenges pwncollege_custom:v1 /bin/bash`
- `docker image prune -f` forcefully removes unused images [optional]
- `-it` keeps STDIN open even if not attached and allocates pseudo-TTY
- `--rm` automatically removes container when it exits
- `--name pwncollege_challenges` assigns name to container
- `pwncollege_custom:v1` custom Docker image from step 1 above
- `/bin/bash` command run by container

3. [optional] Connect to Running Container
> `docker exec -it pwncollege_challenges /bin/bash`

## In Docker Container
4. Copy ELF binary, then set privileges and setuid
> `sudo cp /challenges/<module_dir>/<elf_binary> / && sudo chmod 4755 /<elf_binary>`
