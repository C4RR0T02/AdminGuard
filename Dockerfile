FROM python:3

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .
EXPOSE 1234
CMD [ "python3", "-m" , "flask", "run", "--app", ".\app\app.py", "host=0.0.0.0", "--port=1234"]