# Virus
A simple polymorphic ELF virus

Works for C, C++, and Rust binaries, static, dynamically linked, or PIE.

## Instructions

To experiment with the virus safely, run the container with docker-compose:

```bash
$ docker-compose run workshop
root@container:/code# make
```
You can run the virus against some test executables in the bin/ directory. Run make again to rebuild/clean them.
