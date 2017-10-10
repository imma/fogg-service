from chalice import Chalice

app = Chalice(app_name='hello')

@app.route('/hello')
def index():
    return {'hello': 'world'}
