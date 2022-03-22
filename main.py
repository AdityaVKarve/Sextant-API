""" MODULES IMPORT """
from unicodedata import name
import jwt
import json


from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from tortoise import fields, Tortoise, run_async
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model
from tortoise.exceptions import DoesNotExist, OperationalError

from models import (
    User,
    Strategy,
    OptionSpread,
    User_Pydantic,
    UserIn_Pydantic,
    Strategy_Pydantic,
    StrategyIn_Pydantic,
    OptionSpread_Pydantic,
    OptionSpreadIn_Pydantic,
)

## Start APP
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI(host="0.0.0.0", port=8080)

secret_key = "secret"


""" HELPER FUNCTIONS """


async def authenticate_user(username: str, password: str):
    """
    Authenticates user.
    """
    user = await User.get(username=username)
    if user is None:
        return False
    if not user.verify_password(password):
        return False
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        user = await User.get(id=payload.get("id"))
        if user is None:
            raise credentials_exception

    except:
        raise credentials_exception
    return await User_Pydantic.from_tortoise_orm(user)


async def create_user_strategy(
    strategy: Strategy_Pydantic, user: User_Pydantic = Depends(get_current_user)
):
    """
    Creates a new strategy for a user.
    """
    user_json = await User.get(id=user.id)
    if user_json is None:
        return None

    alloc_strat = await Strategy.get(id=strategy.id)
    user_obj = await User.update_or_create(user_json)

    await user_obj[0].allocated_strategies.add(alloc_strat)
    # User.alloc_strategies is a ManyToManyRelation field, so we need to use the through model to create the relationship between the two models.
    return await User_Pydantic.from_tortoise_orm(user_obj[0])


""" ROUTES """


@app.get("/")
async def index():
    return {"message": "FINVANT RESEARCH CAPITAL API"}


## Route to generate access token
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    user_obj = await User_Pydantic.from_tortoise_orm(user)
    access_token = jwt.encode(user_obj.dict(), secret_key)
    return {"access_token": access_token, "token_type": "bearer"}


## Route to create a new user
@app.post("/users/create", response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(
        username=user.username,
        password_hash=bcrypt.hash(user.password_hash),
    )
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)


## Route to get a user by id
@app.get("/users/{user_id}", response_model=User_Pydantic)
async def get_user(user_id: int, user: User_Pydantic = Depends(get_current_user)):
    try:
        user_obj = await User.get(id=user_id)
        return await User_Pydantic.from_tortoise_orm(user_obj)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")


## Route to get current logged-in user
@app.get("/users/current/", response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user


## Route to allocate a strategy to a user using strategy id and user id as query params
@app.post("/users/allocate/", response_model=User_Pydantic)
async def allocate_strategy(
    user_id: int, strategy_id: int, user: User_Pydantic = Depends(get_current_user)
):
    user = await User.get(id=user_id)
    strategy = await Strategy.get(id=strategy_id)
    await create_user_strategy(strategy, user)
    return await User_Pydantic.from_tortoise_orm(user)


## Route to create a new strategy
@app.post("/strategies/create", response_model=Strategy_Pydantic)
async def create_strategy(
    strategy: StrategyIn_Pydantic, user: User_Pydantic = Depends(get_current_user)
):
    strategy_obj = await Strategy.create(**strategy.dict())
    print("Strategy created by: ", user.username)
    return await Strategy_Pydantic.from_tortoise_orm(strategy_obj)


## Route to get a strategy by id
@app.get("/strategies/{strategy_id}", response_model=Strategy_Pydantic)
async def get_strategy(
    strategy_id: int, user: User_Pydantic = Depends(get_current_user)
):
    try:
        strategy_obj = await Strategy.get(id=strategy_id)
        return await Strategy_Pydantic.from_tortoise_orm(strategy_obj)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="Strategy not found")


## Route to get all option spreads
@app.get("/option_spreads/all")
async def get_option_spreads(user: User_Pydantic = Depends(get_current_user)):
    ## Retrun all option spreads names and ids
    try:
        option_spreads = await OptionSpread.all()
        ## store the option spreads in a list and return the list as json
        option_spreads_list = []
        for option_spread in option_spreads:
            option_spreads_list.append(
                {
                    "id": option_spread.id,
                    "name": option_spread.name,
                    "leg_count": option_spread.leg_count,
                    "legs": option_spread.legs,
                }
            )
        # for option in option_spreads:
        #    print((await OptionSpread_Pydantic.from_tortoise_orm(option)))
        # print(option_spreads_list)
        return option_spreads_list

    except DoesNotExist:
        raise HTTPException(status_code=404, detail="Option Spread not found")


## Route to create a new option spread
@app.post("/option_spreads/create", response_model=OptionSpread_Pydantic)
async def create_option_spread(
    option_spread: OptionSpreadIn_Pydantic,
    user: User_Pydantic = Depends(get_current_user),
):
    option_obj = await OptionSpread.create(**option_spread.dict())
    ## Update the leg_count field of the option spread using count_legs function
    option_obj.count_legs()
    return await OptionSpread_Pydantic.from_tortoise_orm(option_obj)


## Route to update an option spread by id or name
@app.put(
    "/option_spreads/update/{option_spread_id}", response_model=OptionSpread_Pydantic
)
async def update_option_spread(
    option_spread_id: int,
    option_spread: OptionSpreadIn_Pydantic,
    user: User_Pydantic = Depends(get_current_user),
):
    try:
        await OptionSpread.filter(id=option_spread_id).update(
            **option_spread.dict(exclude_unset=True)
        )
        return await OptionSpread_Pydantic.from_queryset_single(
            OptionSpread.get(id=option_spread_id)
        )
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="Option Spread not found")


## Route to delete an option spread by id
@app.delete("/option_spreads/delete/{option_spread_id}")
async def delete_option_spread(
    option_spread_id: int, user: User_Pydantic = Depends(get_current_user)
):
    try:
        await OptionSpread.filter(id=option_spread_id).delete()
        return {"message": "Option Spread deleted"}
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="Option Spread not found")


""" DATABASE SETUP """
register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={"models": ["models"]},
    generate_schemas=True,
    add_exception_handlers=True,
)