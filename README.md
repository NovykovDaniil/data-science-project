
# Powerhouse LLM

[![MIT License](https://img.shields.io/badge/license-MIT-green)](https://github.com/Unfeir/goit_llm/LICENSE)
![Version](https://img.shields.io/badge/version-v0.1.0-green)

## Installation
1. Clone the project repository:
```
git clone <repository_url>
```

2. Navigate to the project directory:
```
cd <project_directory>
```
3. Install the project dependencies using requirements.txt:
```
pip install -r requirements.txt

```

## Launching
To launch the development server and start the FastAPI project, follow these steps:
1. Add .env file to the folder /data_project_chat. It should contain:
```
SECRET_KEY=

DB_ENGINE=django.db.backends.postgresql_psycopg2
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=567234
DB_HOST=127.0.0.1
DB_PORT=5432

ELASTIC_CLOUD_ID=
ELASTIC_LOGIN=
ELASTIC_PASSWORD=

HUGGING_EMAIL=
HUGGING_PASSWORD=
```
2. Run this command in CMD to create a docker container of PostgreSQL
```
docker run --name noteapp-postgres -p 5432:5432 -e POSTGRES_PASSWORD=567234 -d postgres
```
3. Make migrations to your DB container:
```
python data_project_chat/manage.py migrate
```
4. Run server:
```
python data_project_chat/manage.py runserver
```
5. Application could be found here: http://127.0.0.1:8000

## Launching as docker image
1. Type this in the command line:
```
docker run novykovdaniil/powerhousellm
```
2. Application could be found here: http://127.0.0.1:8000

## Application features

A web service with a built-in LLM, which is able to answer user questions according to the loaded context. At the moment, you can download files with the following extension: .txt, .docx, .pdf. The context will be written to a vectorized database and attached to the user's current chat. The model answers questions regardless of the context language. As a bonus, we added a "HugChat" section, which is an interaction with the HuggingChat API project.


### Used technologies
- Python 
- Django 
- Transformers
- PyTorch
- PyPlanger
- JavaScript
- HTML/CSS
- PostgreSQL
- Docker for quick and simple development

......


### Developers - Fast Rabbit Team
- [Daniil Novykov](https://github.com/NovykovDaniil)
- [Kateryna Dehtiarova](https://github.com/KetrinDG)
- [Victor Ivanov](https://github.com/VAlduinV)
- [Andrii Oliinyk](https://github.com/Andrii-Oliinyk-2726)

#### License
This project is licensed under the MIT License.
