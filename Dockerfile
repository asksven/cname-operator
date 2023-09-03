FROM python:3.11
ADD requirements.txt /
RUN pip install -r requirements.txt
ADD cname_operator.py /src/
CMD kopf run -A /src/cname_operator.py