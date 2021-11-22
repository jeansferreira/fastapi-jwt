### Protegendo FastAPI com Autenticação Baseada em Token JWT

  180  cd fastapi-jwt
  173  source venv/bin/activate
  174  export PYTHONPATH=$PWD
  177  pip freeze > requeriments.txt
  178  python main.py

Neste tutorial, você aprenderá a proteger um aplicativo FastAPI ativando a autenticação usando JSON Web Tokens (JWTs). Usaremos o PyJWT para assinar, codificar e decodificar tokens JWT.

Autenticação no FastAPI
Autenticação é o processo de verificar os usuários antes de conceder-lhes acesso a recursos seguros. Quando um usuário é autenticado, ele tem permissão para acessar recursos seguros não abertos ao público.

Estaremos analisando a autenticação de um aplicativo FastAPI com autenticação Bearer (ou baseada em Token), que envolve a geração de tokens de segurança chamados tokens portador. Os tokens portadores, neste caso, serão JWTs.

A autenticação no FastAPI também pode ser tratada pelo OAuth.
Configuração Inicial
Comece criando uma nova pasta para manter seu projeto chamada "fastapi-jwt":

$ mkdir fastapi-jwt
$ cd fastapi-jwt
Em seguida, crie e ative um ambiente virtual:

$ python3.9 -m venv venv
$ source venv/bin/activate
(venv)$ export PYTHONPATH=$PWD
Sinta-se à vontade para trocar virtualenv e Pip por Poesia ou Pipenv. Para mais informações, revise Modern Python Environments.
Instale FastAPI e Uvicorn:

(venv)$ pip install fastapi==0.62.0 uvicorn==0.12.3
Em seguida, crie os seguintes arquivos e pastas:

fastapi-jwt
├── app
│   ├── __init__.py
│   ├── api.py
│   ├── auth
│   │   └── __init__.py
│   └── model.py
└── main.py
No arquivo main.py, defina um ponto de entrada para executar o aplicativo:

# main.py

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.api:app", host="0.0.0.0", port=8081, reload=True)
Aqui, instruímos o arquivo a executar um servidor Uvicorn na porta 8081 e recarregar a cada alteração de arquivo.

Antes de iniciar o servidor através do arquivo de ponto de entrada, crie uma rota base em app/api.py:

# app/api.py

from fastapi import FastAPI

app = FastAPI()

@app.get("/", tags=["root"])
async def read_root() -> dict:
    return {"message": "Welcome to your blog!."}
Execute o arquivo de ponto de entrada do seu terminal:

(venv)$ python main.py
Navegue até http://localhost:8081 no seu navegador. Você deve ver:

{
    "message": "Welcome to your blog!."
}
O que estamos construindo?
Para o restante deste tutorial, você criará um aplicativo CRUD de miniblog seguro para criar e ler postagens de blog. No final, você terá:

aplicativo final

Modelos
Antes de prosseguirmos, vamos definir um modelo pydantic para os posts.

Em model.py, adicione:

# app/model.py

from pydantic import BaseModel, Field, EmailStr


class PostSchema(BaseModel):
    id: int = Field(default=None)
    title: str = Field(...)
    content: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "title": "Securing FastAPI applications with JWT.",
                "content": "In this tutorial, you'll learn how to secure your application by enabling authentication using JWT. We'll be using PyJWT to sign, encode and decode JWT tokens...."
            }
        }
Rotas
GET Rota

Start by importing the PostSchema then adding a list of dummy posts and an empty user list variable in app/api.py:

# app/api.py

from app.model import PostSchema

posts = [
    {
        "id": 1,
        "title": "Pancake",
        "content": "Lorem Ipsum ..."
    }
]

users = []
Em seguida, adicione os manipuladores de rotas para obter todas as postagens e uma postagem individual por ID:

# app/api.py

@app.get("/posts", tags=["posts"])
async def get_posts() -> dict:
    return { "data": posts }


@app.get("/posts/{id}", tags=["posts"])
async def get_single_post(id: int) -> dict:
    if id > len(posts):
        return {
            "error": "No such post with the supplied ID."
        }

    for post in posts:
        if post["id"] == id:
            return {
                "data": post
            }
app/api.py agora deve ficar assim:

# app/api.py

from fastapi import FastAPI

from app.model import PostSchema


posts = [
    {
        "id": 1,
        "title": "Pancake",
        "content": "Lorem Ipsum ..."
    }
]

users = []

app = FastAPI()


@app.get("/", tags=["root"])
async def read_root() -> dict:
    return {"message": "Welcome to your blog!."}


@app.get("/posts", tags=["posts"])
async def get_posts() -> dict:
    return { "data": posts }


@app.get("/posts/{id}", tags=["posts"])
async def get_single_post(id: int) -> dict:
    if id > len(posts):
        return {
            "error": "No such post with the supplied ID."
        }

    for post in posts:
        if post["id"] == id:
            return {
                "data": post
            }
Teste manualmente as rotas em http://localhost:8081/posts e http://localhost:8081/posts/1

Rota POST

Logo abaixo das rotas GET, adicione o seguinte manipulador para criar uma nova postagem:

# app/api.py

@app.post("/posts", tags=["posts"])
async def add_post(post: PostSchema) -> dict:
    post.id = len(posts) + 1
    posts.append(post.dict())
    return {
        "data": "post added."
    }
Com o backend em execução, teste a rota POST através dos documentos interativos em http://localhost:8081/docs.

Você também pode testar com curl:

$ curl -X POST http://localhost:8081/posts \
    -d  '{ "id": 2, "title": "Lorem Ipsum tres", "content": "content goes here"}' \
    -H 'Content-Type: application/json'
Você deve ver:

{
    "data": [
        "post added."
    ]
}
Autenticação JWT
Nesta seção, criaremos um manipulador de tokens JWT e uma classe para lidar com tokens portadores.

Antes de começar, instale o PyJWT, para codificar e decodificar JWTs. Também usaremos andpython-decouple para ler variáveis de ambiente:

(venv)$ pip install PyJWT==1.7.1 python-decouple==3.3
Manipulador JWT

O manipulador JWT será responsável por assinar, codificar, decodificar e retornar tokens JWT. Na pasta "auth", crie um arquivo chamado auth_handler.py:

# app/auth/auth_handler.py

import time
from typing import Dict

import jwt
from decouple import config


JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")


def token_response(token: str):
    return {
        "access_token": token
    }
In the code block above, we imported the time, typing, jwt, and decouple modules. The time module is responsible for setting an expiry for the tokens. Every JWT has an expiry date and/or time where it becomes invalid. The jwt module is responsible for encoding and decoding generated token strings. Lastly, the token_response function is a helper function for returning generated tokens.

Os JSON Web Tokens são codificados em strings a partir de uma carga útil do dicionário.
Segredo e Algoritmo JWT
Em seguida, crie um arquivo de ambiente chamado .env no diretório base:

secret=please_please_update_me_please
algorithm=HS256
O segredo no arquivo de ambiente deve ser substituído por algo mais forte e não deve ser divulgado. Por exemplo:

>>> import os
>>> import binascii
>>> binascii.hexlify(os.urandom(24))
b'deff1952d59f883ece260e8683fed21ab0ad9a53323eca4f'
A chave secreta é usada para codificar e decodificar strings JWT.

O valor do algoritmo, por outro lado, é o tipo de algoritmo usado no processo de codificação.

De volta auth_handler.py, adicione a função para assinar a string JWT:

# app/auth/auth_handler.py

def signJWT(user_id: str) -> Dict[str, str]:
    payload = {
        "user_id": user_id,
        "expires": time.time() + 600
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token_response(token)
In the signJWT function, we defined the payload, a dictionary containing the user_id passed into the function, and an expiry time of ten minutes from when it is generated. Next, we created a token string comprising of the payload, the secret, and the algorithm type and then returned it.

Em seguida, adicione a função decodeJWT:

# app/auth/auth_handler.py

def decodeJWT(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        return {}
The decodeJWT function takes the token and decodes it with the aid of the jwt module and then stores it in a decoded_token variable. Next, we returned decoded_token if the expiry time is valid, otherwise, we returned None.

Um JWT não é criptografado. É baseado em 64 codificado e assinado. Assim, qualquer um pode decodificar o token e usar seus dados. Mas apenas o servidor pode verificar sua autenticidade usando o JWT_SECRET.
Registro e Login de Usuário
Seguindo em frente, vamos conectar as rotas, esquemas e ajudantes para lidar com o registro e login do usuário.

Em model.py, adicione o esquema do usuário:

# app/model.py

class UserSchema(BaseModel):
    fullname: str = Field(...)
    email: EmailStr = Field(...)
    password: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "fullname": "Abdulazeez Abdulazeez Adeshina",
                "email": "abdulazeez@x.com",
                "password": "weakpassword"
            }
        }

class UserLoginSchema(BaseModel):
    email: EmailStr = Field(...)
    password: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "email": "abdulazeez@x.com",
                "password": "weakpassword"
            }
        }
Em seguida, atualize as importações em app/api.py:

# app/api.py

from fastapi import FastAPI, Body

from app.model import PostSchema, UserSchema, UserLoginSchema
from app.auth.auth_handler import signJWT
Adicione a rota de registro do usuário:

# app/api.py

@app.post("/user/signup", tags=["user"])
async def create_user(user: UserSchema = Body(...)):
    users.append(user) # replace with db call, making sure to hash the password first
    return signJWT(user.email)
Como estamos usando um validador de e-mail, EmailStr, instale o validador de e-mail:

(venv)$ pip install "pydantic[email]"
Execute o servidor:

(venv)$ python main.py
Teste-o através da documentação interativa em http://localhost:8081/docs.

inscrever-se usuário

Em um ambiente de produção, certifique-se de hash sua senha usando bcrypt ou passlib antes de salvar o usuário no banco de dados.
Em seguida, defina uma função auxiliar para verificar se existe um usuário:

# app/api.py

def check_user(data: UserLoginSchema):
    for user in users:
        if user.email == data.email and user.password == data.password:
            return True
    return False
A função acima verifica se existe um usuário antes de criar um JWT com o e-mail de um usuário.

Em seguida, defina a rota de login:

# app/api.py

@app.post("/user/login", tags=["user"])
async def user_login(user: UserLoginSchema = Body(...)):
    if check_user(user):
        return signJWT(user.email)
    return {
        "error": "Wrong login details!"
    }
Teste a rota de login primeiro criando um usuário e depois fazendo login:

faça login do usuário

Como os usuários são armazenados na memória, você terá que criar um novo usuário toda vez que o aplicativo for recarregado para testar o login.
Protegendo Rotas
Com a autenticação em vigor, vamos proteger a rota de criação.

Portador JWT

Now we need to verify the protected route, by checking whether the request is authorized or not. This is done by scanning the request for the JWT in the Authorization header. FastAPI provides the basic validation via the HTTPBearer class. We can use this class to extract and parse the token. Then, we'll verify it using the decodeJWT function defined in app/auth/auth_handler.py.

Crie um novo arquivo na pasta "auth" chamado auth_bearer.py:

# app/auth/auth_bearer.py

from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .auth_handler import decodeJWT


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str) -> bool:
        isTokenValid: bool = False

        try:
            payload = decodeJWT(jwtoken)
        except:
            payload = None
        if payload:
            isTokenValid = True
        return isTokenValid
So, the JWTBearer class is a subclass of FastAPI's HTTPBearer class that will be used to persist authentication on our routes.

Init
No método __init__, ativamos o relatório automático de erros definindo o booleanauto_error como True.

Chamada
In the __call__ method, we defined a variable called credentials of type HTTPAuthorizationCredentials, which is created when the JWTBearer class is invoked. We then proceeded to check if the credentials passed in during the course of invoking the class are valid:

Se o esquema de credenciais não for um esquema ao portador, levantamos uma exceção para um esquema de token inválido.
Se um token portador foi passado, verificamos que o JWT é válido.
Se nenhuma credencial fosse recebida, geramos um erro de autorização inválido.
Verificar
The verify_jwt method verifies whether a token is valid. The method takes a jwtoken string which it then passes to the decodeJWT function and returns a boolean value based on the outcome from decodeJWT.

Injeção de dependência

Para proteger as rotas, aproveitaremos a injeção de dependências via FastAPI's Depends.

Comece atualizando as importações adicionando a classe JWTBearer, bem como Depends:

# app/api.py

from fastapi import FastAPI, Body, Depends

from app.model import PostSchema, UserSchema, UserLoginSchema
from app.auth.auth_bearer import JWTBearer
from app.auth.auth_handler import signJWT
In the POST route, add the dependencies argument to the @app property like so:

# app/api.py

@app.post("/posts", dependencies=[Depends(JWTBearer())], tags=["posts"])
async def add_post(post: PostSchema) -> dict:
    post.id = len(posts) + 1
    posts.append(post.dict())
    return {
        "data": "post added."
    }
Atualize a página de documentos interativos:

arrogância ui

Teste a autenticação tentando visitar uma rota protegida sem passar um token:

adicionar usuário não autenticado

Crie um novo usuário e copie o token de acesso gerado:

token de acesso

Depois de copiá-lo, clique no botão autorizar no canto superior direito e cole o token:

autorizar

Agora você deve ser capaz de usar a rota protegida:

adicionar usuário autenticado

Conclusão
Este tutorial cobriu o processo de proteger um aplicativo FastAPI com JSON Web Tokens. Você pode encontrar o código-fonte no repositório fastapi-jwt. Obrigado pela leitura.

Procurando alguns desafios?

Hash as senhas antes de salvá-las usando bcrypt ou passlib.
Mova os usuários e postagens do armazenamento temporário para um banco de dados como MongoDB ou Postgres. Você pode seguir as etapas em Construindo um aplicativo CRUD com FastAPI e MongoDB para configurar um banco de dados MongoDB e implantar no Heroku.
Adicione tokens de atualização para emitir automaticamente novos JWTs quando expirarem. Não sabe por onde começar? Confira esta explicação do autor de Flask-JWT.
Adicione rotas para atualizar e excluir postagens.

https://testdriven.io/blog/fastapi-jwt-auth/