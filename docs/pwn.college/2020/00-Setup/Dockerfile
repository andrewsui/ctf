FROM pwncollege/pwncollege_challenge:latest
RUN git clone https://github.com/pwncollege/challenges.git
RUN chown root:sudo /usr/bin/sudo
RUN chmod 4770 /usr/bin/sudo
RUN usermod -aG sudo ctf && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER ctf
WORKDIR /home/ctf
RUN sudo rm .gdbinit && echo "set pagination off\nset disassembly-flavor intel" > .gdbinit
RUN sudo rm .radare2rc && echo "e io.cache=true\ne scr.color=3\ne scr.utf8=true\ne scr.utf8.curvy=true\ne cfg.fortunes.type=tips" > .radare2rc
RUN sudo rm .tmux.conf && sudo rm .sudo_as_admin_successful
RUN echo "syntax on\nset number\nset relativenumber\nset expandtab\nset autoindent\nset shiftwidth=4\nset softtabstop=4\nset tabstop=8" > .vimrc
