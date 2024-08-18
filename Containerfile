FROM docker.io/python:3.9-slim

COPY app/requirements.txt /opt/app/requirements.txt

RUN pip install --trusted-host pypi.python.org -r /opt/app/requirements.txt

COPY app /opt/app

CMD [ "python", "/opt/app/zte_exporter.py" ]
