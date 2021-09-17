FROM ubuntu:latest

# so apt uses default answers for any questions
ENV DEBIAN_FRONTEND=noninteractive

# Install useful tools
RUN apt update
RUN apt install -y vim gcc gdb make fasm strace xxd git python3 rustc golang

# set up gdb
RUN echo "set disassembly-flavor intel" > /root/.gdbinit

# install gdb-peda
RUN git clone https://github.com/longld/peda.git ~/peda
RUN echo "source ~/peda/peda.py" >> /root/.gdbinit

WORKDIR "/code"

CMD ["/bin/bash"]
