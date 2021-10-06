from datetime import date, timedelta

"""
Here the function calculates the data as -{"created_at": "2021-02-19","count": 1} from start date to end date 
with the object as the queryset of the Booking or the User passed
"""


def dashboard_function_count(object, start_date, end_date):
    delta = timedelta(days=1)
    start_date = date(start_date.year, start_date.month, start_date.day)
    end_date = date(end_date.year, end_date.month, end_date.day)
    date_list = []
    object_list = list(object)
    for k in object:
        date_list.append(k['created_at'])
    while start_date <= end_date - delta:
        if start_date not in date_list:
            object_list.append({'created_at': start_date, 'count': 0})
        start_date += delta
    return object_list


def dashboard_function_aggregate_per_day(object, start_date, end_date):
    delta = timedelta(days=1)
    start_date = date(start_date.year, start_date.month, start_date.day)
    end_date = date(end_date.year, end_date.month, end_date.day)
    date_list = []
    object_list = list(object)
    for k in object:
        date_list.append(k['payment_perday_date'])
    while start_date < end_date:
        if start_date not in date_list:
            object_list.append({'payment_perday_date': start_date, 'amount_perday__sum': 0})
        start_date += delta
    return object_list
