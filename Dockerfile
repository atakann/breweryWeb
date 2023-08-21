FROM python:3.9

WORKDIR /usr/src/app/brewerybook

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the content of the local src directory to the working directory
COPY . /usr/src/app/

# Specify the command to run on container start
CMD ["gunicorn", "brewerybook.wsgi:application", "--bind", "0.0.0.0:8000"]