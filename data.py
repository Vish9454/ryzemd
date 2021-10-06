from django.db.models import Q
from config.wsgi import application
from apps.accounts.models import State,City
from django.db.models import F


with open('/home/motu/Desktop/projects/ryzemd-backend/states.json') as json_file:
    result = json_file.read()
    result = eval(result)

for i in result:
    if i['country_id']==233:
        State.objects.create(state_name=i['name'],id=i['id'])
    
with open('/home/motu/Desktop/projects/ryzemd-backend/cities.json') as json_file:
    result = json_file.read()
    result = eval(result)

for i in result:
    state_obj = State.objects.filter(id=i['state_id']).first()
    if state_obj:
        City.objects.create(city_name=i['name'],state_id=state_obj)


#deleting states that have 0 cities
State.objects.filter(~Q(state__state_id=F('id'))).delete()