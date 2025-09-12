import json

import bcrypt
import jwt
import phonenumbers
from django.core.handlers.wsgi import WSGIRequest
from django.http import JsonResponse
from django.http.response import Http404
from django.views.decorators.csrf import csrf_exempt
import django.core.exceptions as django_exception
from django.db import IntegrityError

from message_auth.models import RefreshToken, User
import utils.helper as helper
from utils.models import CustomException
from message_controller.models import Snapshot


@csrf_exempt
def create_user(req: WSGIRequest):
    try:
        if req.method == 'POST':
            data = json.loads(req.body)

            # trim string input except password
            input_data = dict((k, v.strip() if v.__class__ is str and not k.__contains__('password') else v) for k, v in data.items())
            username = input_data.get('username')
            country_code = input_data.get('country_code')
            phone_number = input_data.get('phone_number')
            client_number = input_data.get('client_number')
            secret_question = input_data.get('secret_question')
            answer = input_data.get('answer')
            password = input_data.get('password')
            confirm_password = input_data.get('confirm_password')

            found_client_snapshot = Snapshot.objects.filter(sim_cards__icontains=client_number)
            if not found_client_snapshot:
                raise CustomException(message='No client has been activated/registered with that number: %s' % client_number)

            parsed_number = phonenumbers.parse(phone_number, region=country_code)
            if not phonenumbers.is_possible_number(parsed_number) or not phonenumbers.is_valid_number(parsed_number):
                raise CustomException(message='Invalid phone number.', status=422)

            if secret_question not in helper.secret_questions:
                raise CustomException(message='Invalid secret question.', status=422)

            if not (5 < len(password) < 17):
                raise CustomException(message='Password must be between 6-16 characters long.', status=422)
            if password != confirm_password:
                raise CustomException(message='Passwords do not match!', status=422)

            salt = bcrypt.gensalt(6)
            hashed_pw = bcrypt.hashpw(bytes(password, 'utf-8'), salt)

            if not answer:
                raise CustomException(message='Answer cannot be empty.', status=422)
            secret_question_data = {'secret_question': secret_question, 'answer': answer}
            client_history = [{'number': client_number}]

            user = User(username=username.casefold(), phone_number=phone_number,
                        client_number=client_number, secret_question=secret_question_data,
                        password=hashed_pw, client_history=client_history)
            user.full_clean()
            user.save()

            return JsonResponse({'success': True, 'message': 'User created successfully'}, status=201)
    except CustomException as err:
        return JsonResponse({'success': False, 'message': err.message}, status=err.status)
    except Exception as err:
        status = 500
        message = err.__str__()
        print(err.__class__, message, sep='\n')

        if err.__class__ is IntegrityError:
            status = 409
            message = "[%s] already exists." % ' '.join(message.split('.')[-1].split('_'))
        elif err.__class__ is django_exception.ValidationError:
            status = 422
        return JsonResponse({'success': False, 'message': message}, status=status)


@csrf_exempt
def login(req: WSGIRequest):
    try:
        if req.method == 'POST':
            data = json.loads(req.body)
            username = data.get('username')
            password = data.get('password')

            found_user = User.objects.get(username=username)

            if not bcrypt.checkpw(bytes(password, 'utf-8'), found_user.password):
                return JsonResponse({'error': 'Invalid username/password.'}, status=400)

            access_token = helper.generate_access_token(found_user)
            refresh_token = helper.generate_refresh_token(found_user)

            if getattr(found_user, 'refreshtoken', None):
                found_user.refreshtoken.token = refresh_token
                found_user.refreshtoken.save()
            else:
                RefreshToken.objects.create(token=refresh_token, user=found_user)

            found_user = {'user_id': found_user.id, 'username': found_user.username, 'phone_number': found_user.phone_number,
                          'client_number': found_user.client_number, 'client_history': found_user.client_history}
            return JsonResponse({'user': found_user, 'access_token': access_token, 'refresh_token': refresh_token}, safe=False)
        return JsonResponse({'error': 'Method not allowed.'}, status=405)

    except (django_exception.ObjectDoesNotExist, Http404):
        return JsonResponse({'error': 'Invalid username/password.'}, status=400)
    except Exception as err:
        print(err.__str__())
        return JsonResponse({'error': 'An error occurred.'}, status=500)


def logout(req: WSGIRequest):
    try:
        if req.method == 'GET':
            user = helper.verify_token(req)
            RefreshToken.objects.filter(user=user).delete()
            token = req.headers.get('Authorization').split(' ')[1]
            if len(helper.black_list) > 999:
                helper.black_list = []
                helper.black_list.append(token)
            else:
                helper.black_list.append(token)
            return JsonResponse({'success': True, 'message': 'Logged out user successfully'}, safe=False)
        return JsonResponse({'error': 'Method not allowed.'}, status=405)
    except (CustomException, Exception) as err:
        if err is CustomException:
            return JsonResponse({'error': err.__str__()}, status=err.status)
        print('logout error: ', err.__str__())
        return JsonResponse({'error': 'Invalid/Expired token error'}, status=400)


def get_refresh_token(req: WSGIRequest):
    try:
        if req.method == 'GET':
            auth_header: str = req.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                raise CustomException('Authentication required', status=400)

            refresh_token = auth_header.split(' ')[1]
            try:
                payload = helper.decode_token(refresh_token)
            except jwt.ExpiredSignatureError as err:
                # if token is expired delete it from db
                found_ref_token = RefreshToken.objects.get(token=refresh_token)
                found_ref_token.delete()
                raise err

            user = User.objects.get(id=payload['user_id'])

            # throws if the user has logged in from a new device without logging out previous active session
            found_ref_token = RefreshToken.objects.get(token=refresh_token, user=user)

            new_access_token = helper.generate_access_token(user)
            new_ref_token = helper.generate_refresh_token(user)
            found_ref_token.token = new_ref_token
            found_ref_token.save()

            user = {'user_id': user.id, 'username': user.username, 'phone_number': user.phone_number,
                    'client_number': user.client_number, 'client_history': user.client_history}
            return JsonResponse({'user': user, 'access_token': new_access_token, 'refresh_token': new_ref_token}, safe=False)

        return JsonResponse({'error': 'Method not allowed.'}, status=405)
    except CustomException as err:
        return JsonResponse({'error': err.__str__()}, status=err.status)
    except Exception as err:
        print('Refresh Token Error: ', err.__str__())
        return JsonResponse({'error': 'Invalid token.'}, status=400)
