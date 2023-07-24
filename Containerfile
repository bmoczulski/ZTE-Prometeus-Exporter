FROM docker.io/python:3.9-slim

COPY app /opt/app

RUN pip install --trusted-host pypi.python.org -r /opt/app/requirements.txt

CMD [ "python", "/opt/app/zte_exporter.py" ]
