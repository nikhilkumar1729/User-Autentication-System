import redis
import json
import time
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Task

r = redis.Redis(host='redis', port=6379, decode_responses=True)

def process_task(number):
    time.sleep(5)  # simulate heavy work
    return number * number

while True:
    _, task_json = r.brpop("task_queue")
    task_data = json.loads(task_json)

    db: Session = SessionLocal()
    task = db.query(Task).filter(Task.id == task_data["task_id"]).first()

    task.status = "PROCESSING"
    db.commit()

    result = process_task(task_data["number"])

    task.status = "COMPLETED"
    task.result = str(result)
    db.commit()

    db.close()
