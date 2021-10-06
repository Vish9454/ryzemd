Ryzemd-backend
=========

# Installation

## Install OS (Ubuntu) Requirements

    
## Clone Project

    git clone <repository> ryzemd-backend

## Virtual Envirnoment and requirements

    virtualenv -p /path/to/python3.7 venv
    source venv/bin/activate
    pip install -r requirements.txt

# Add Local Settings

    cp config/local.py.example config/local.py
    
    Add all keys and settings in local.py

## Postgres setup

    pip install psycopg2
    sudo su - postgres
    psql -d template1 -U postgres
    CREATE USER your-username WITH PASSWORD your-password;
    ALTER USER your-username WITH SUPERUSER;
    CREATE DATABASE db_name;
    ALTER ROLE your-username SET client_encoding TO 'utf8';
    ALTER ROLE your-username SET default_transaction_isolation TO 'read committed';
    ALTER ROLE your-username SET timezone TO 'UTC';
    GRANT ALL PRIVILEGES ON DATABASE db_name TO your-username;
    \q
    psql -d mu_db -U your-username


## run migrations
   
   python manage.py migrate

## Create a superuser account.

    python manage.py createsuperuser


## Load fixtures

   python manage.py loaddata fixtures/*.json

## Convert to json
    csvtojson.py is used for converting .csv file to .json 
    python csvtojson.py

## Load .json to database
    "jsontodb.py"
 This script is used to load json data to database
 
## Running Development Server

    python manage.py runserver

## setting up the environment

We have used sql debugger to monitor the duplicate sql queries for that you need to install the django-debug-toolbar tool which is there in requirement.txt. You can read more about django debugger here https://django-debug-toolbar.readthedocs.io/en/latest/

For enabling django debugger we have to add additional urls which we have place in project's urls.py under if condition where it checks whether debug is true or not.



**Note:** Never forget to enable virtual environment (`source venv/bin/activate`) before running above command and use settings accordingly.


## Custom fields at frontend

In this, we have given frontend choice to select fields in response. They can pass below as query params and they will be getting only those fields in response. ?fields=('id','email')

Note:- Admin signup is restricted. To create an admin inform backend user

Note:- visit start time will be in format as hh:00:00 or hh:30:00,
       visit end time can be any time
       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
