FROM debian:9

RUN useradd scoreboard -m -s /bin/bash
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y nginx python3-pip supervisor

RUN mkdir /srv/web/ && \
    chown scoreboard:www-data /srv/web/ && \
    mkdir /home/scoreboard/logs/ && \
    chown scoreboard:scoreboard /home/scoreboard/logs/

ADD ./deploy/requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt && rm /tmp/requirements.txt

ADD ./deploy/supervisor.gunicorn /etc/supervisor/conf.d/gunicorn.conf
ADD ./deploy/nginx-site /etc/nginx/sites-available/scoreboard

WORKDIR /home/scoreboard

RUN ln -s /etc/nginx/sites-available/scoreboard /etc/nginx/sites-enabled && \
    rm /etc/nginx/sites-enabled/default

ADD app ./inshack-scoreboard
RUN chown scoreboard:scoreboard ./inshack-scoreboard -R
RUN cd inshack-scoreboard && python3 manage.py collectstatic --noinput

EXPOSE 8081

CMD sed -i -e "s/{{HOST}}/$db_host/" -e "s/{{USER}}/$db_user/" -e "s/{{PASSWORD}}/$db_password/" -e "s/{{SECRET_KEY}}/$SECRET_KEY/" -e "s/{{ALLOWED_HOST}}/$ALLOWED_HOST/" /etc/supervisor/conf.d/gunicorn.conf && \
    service supervisor start && \
    service nginx restart && \
    bash -c "tail -f {/var/log/nginx/scoreboard.*.log,/home/scoreboard/logs/error,/home/scoreboard/logs/access}"
