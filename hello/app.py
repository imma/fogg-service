from chalice import Chalice

app = Chalice(app_name='hello')

@app.route('*')
def index():
    return {'hello': 'world'}
