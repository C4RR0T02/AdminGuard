FROM python:3.10

# Copy only the necessary files (excluding those specified in .dockerignore)
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Set the FLASK_APP environment variable
ENV FLASK_APP=./app/app.py

# Expose port 8080
EXPOSE 8080

# Run the application
CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0", "--port=8080"]