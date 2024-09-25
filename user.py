from fastapi import APIRouter

# Create a router object
router = APIRouter()

# Define a route within this router
@router.get('/')
def root():
    return {'message': 'This is the Base URL'}

@router.get('/Ungaboonga')
def ungaboonga():
    return {'message': 'UNGABOONGA HERE'}
