from django.db import models
from datetime import datetime
import re
import bcrypt

class UserManager(models.Manager):
    def validate(self, form):
        errors = {}
        if len(form['fname']) < 2: 
            errors['fname'] = "Your first name must be at least 2 characters"
        if len(form['lname']) < 2:
            errors['lname'] = "Your last name must be at least 2 characters"
        if len(form['password']) < 8:
            errors['password'] = "Your password must be at least 8 characters"
        if int(form['age']) < 13:
            errors['age'] = "Your must be 13 yrs old at least"
        if datetime.strptime(form['birth_date'], '%Y-%m-%d') > datetime.now():
            errors['birth_date'] = "Enter correct birthday, date should be in the past"

        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')    
        if not EMAIL_REGEX.match(form['email']):
            errors['email'] = 'Invalid Email Address'
        
        email_check = self.filter(email=form['email'])
        if email_check:
            errors['email'] = "Email already in use"
        
        if form['password'] != form['confpw']:
            errors['password'] = 'Password and Confirm Password do not match'
        return errors
    
    def authenticate(self, email, password):
        users = self.filter(email=email)
        if not users:
            return False

        user = users[0]
        return bcrypt.checkpw(password.encode(), user.password.encode())

    def register(self, form):
        pw = bcrypt.hashpw(form['password'].encode(), bcrypt.gensalt()).decode()
        return self.create(
            first_name = form['fname'],
            last_name = form['lname'],
            birth_date = form['birth_date'],
            age = form['age'],
            email = form['email'],
            password = pw
        )
        
class User(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    birth_date = models.DateField(null=True)
    age = models.IntegerField(null=False)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)

    objects = UserManager()
