import datetime
import json

from django.core.handlers.wsgi import WSGIRequest
from django.db import IntegrityError
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import django.core.exceptions as django_exception


from message_controller.models import Snapshot
import utils.helper as utils


# Create your views here.


def get_client_snapshot(req, mobile_number):
    try:
        utils.verify_token(req)
        found_snapshots = Snapshot.objects.filter(sim_cards__icontains=mobile_number)
        if not found_snapshots:
            raise django_exception.ObjectDoesNotExist()

        data = found_snapshots[0]
        return JsonResponse({'android_id': data.android_id, 'brand': data.brand, 'sim_cards': data.sim_cards,
                             'message_snapshot': data.message_snapshot,
                             'date': data.date})
    except (django_exception.ObjectDoesNotExist, Exception) as err:
        if err.__class__ is django_exception.ObjectDoesNotExist:
            return JsonResponse('Snapshot was not found :(', safe=False, status=404)

        print(err.__str__())
        return JsonResponse({'error': err.__str__()}, safe=False, status=401)


def get_snapshots(req):
    snapshots = Snapshot.objects.all()

    if 1 > len(snapshots):
        return JsonResponse([], safe=False)

    return JsonResponse([{'android_id': data.android_id, 'brand': data.brand, 'sim_cards': data.sim_cards, 'message_snapshot': data.message_snapshot,
                          'date': data.date} for data in snapshots], safe=False)


@csrf_exempt
def post_snapshot(req: WSGIRequest):
    try:
        if req.method == 'POST':
            data = json.loads(req.body)
            android_id = data.get('android_id')
            brand = data.get('brand')
            sim_cards = data.get('mobile_numbers')
            message_snapshot = data.get('snapshot_messages')

            print('HEADERS -> ', req.headers)

            def new_snapshot() -> Snapshot:
                return Snapshot(
                    android_id=android_id,
                    brand=brand,
                    sim_cards=sim_cards,
                    message_snapshot=message_snapshot
                )

            try:
                found_snapshot = Snapshot.objects.get(android_id=android_id)

            except django_exception.ObjectDoesNotExist:
                found_snapshot = None

            if found_snapshot is None:
                # create new Snapshot
                new_snapshot().save()

            else:
                # same device but new sim_card was detected
                if found_snapshot.sim_cards != sim_cards:
                    found_snapshot.delete()
                    new_snapshot().save()

                elif found_snapshot.message_snapshot == message_snapshot:
                    raise IntegrityError('Conflict resource: [message_snapshot]')

                else:
                    found_snapshot.message_snapshot = message_snapshot
                    found_snapshot.save()

            print('RECEIVED POST REQUEST', datetime.datetime.now())

            return JsonResponse({'success': True, 'message': 'Snapshot added successfully'})

        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    except Exception as err:
        if type(err) == IntegrityError:
            return JsonResponse({'success': False, 'message': err.__str__()}, status=409)
        return JsonResponse({'success': False, 'message': err.__str__()}, status=500)
