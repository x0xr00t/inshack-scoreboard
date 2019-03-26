# inshack-scoreboard
A Django scoreboard for CTF

## Build

```bash
docker build -t registry.insecurity-insa.fr/insecurity/scoreboard -f deploy/Dockerfile .
```

## Setup the DB on a separate server

```bash
$ docker run -it --rm -p 3306:3306 \
  -e MYSQL_DATABASE=inshack \
  -e MYSQL_USER=inshack \
  -e MYSQL_PASSWORD=password \
  -e MYSQL_RANDOM_ROOT_PASSWORD=yes \
  mysql:5.7
```

Modify *inshack_scoreboard/settings.py* accordingly. Then launch the migrations on the mysql host:

```bash
$ python3 manage.py makemigrations
$ python3 manage.py migrate
```

## Populate DB

```bash
echo "from django.contrib.auth.models import User; \
from challenges.models import CTFSettings; \
User.objects.create_superuser('adminctf', 'me@gmail.com', 'CHANGE_ME'); \
CTFSettings.objects.create(url_challenges_state='http://IP_OF_CHALLENGE_MONITORING/')
" | python3 manage.py shell
```

## Run

```bash
docker run --rm -it --name scoreboard -p 80:8081 registry.insecurity-insa.fr/insecurity/scoreboard
```
