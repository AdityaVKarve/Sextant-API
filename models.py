from tortoise import fields, models
from tortoise.models import Model
from tortoise.contrib.pydantic import pydantic_model_creator

from passlib.hash import bcrypt
from typing import List, Optional, Union

""" SCHEMA """


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=20, unique=True)
    password_hash = fields.CharField(max_length=100)
    allocated_strategies: fields.ManyToManyRelation[
        "Strategy"
    ] = fields.ManyToManyField("models.Strategy", through="models.User_Strategy")

    class Meta:
        table = "users"

    def __str__(self):
        return self.username

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


class Strategy(Model):
    id = fields.IntField(pk=True)
    indicators = fields.JSONField()
    allocate_capital = fields.DecimalField(max_digits=10, decimal_places=2)
    leverage = fields.DecimalField(max_digits=10, decimal_places=2)
    dataset = fields.CharField(max_length=100)

    class Meta:
        table = "strategies"

    def __str__(self):
        return self.indicators


class OptionSpread(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=100)
    leg_count = fields.IntField()
    # legs is a list of lists
    legs: List[List[Union[str, int, float]]] = fields.JSONField()

    class Meta:
        table = "option_spreads"

    def count_legs(self):
        ## Set the leg_count as the length of the legs list
        self.leg_count = int(len(self.legs))
        return self.leg_count

    class PydanticMeta:
        computed = ["count_legs"]

    def __str__(self):
        return self.name


## Pydantic Models
## USERS
User_Pydantic = pydantic_model_creator(User, name="User")  ## User_Pydantic = User Model
UserIn_Pydantic = pydantic_model_creator(
    User, name="UserIn", exclude_readonly=True
)  ## Incoming

## STRATEGIES
Strategy_Pydantic = pydantic_model_creator(
    Strategy, name="Strategy"
)  ## Strategy_Pydantic = Strategy Model
StrategyIn_Pydantic = pydantic_model_creator(
    Strategy, name="StrategyIn", exclude_readonly=True
)  ## Incoming

## OPTION SPREADS
OptionSpread_Pydantic = pydantic_model_creator(OptionSpread, name="OptionSpread")
OptionSpreadIn_Pydantic = pydantic_model_creator(
    OptionSpread, name="OptionSpreadIn", exclude_readonly=True
)  # Incoming
