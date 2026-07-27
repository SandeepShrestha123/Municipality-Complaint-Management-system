from flask import Flask, render_template, request
import folium

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/map', methods=['POST'])
def map_view():
    latitude = float(request.form['latitude'])
    longitude = float(request.form['longitude'])
    m = folium.Map(location=[latitude, longitude], zoom_start=13)
    folium.Marker([latitude, longitude], popup='You are here').add_to(m)
    map_html = "templates/map.html"
    m.save(map_html)
    return render_template('map.html')
 
if __name__ == '__main__':
    app.run(debug=True)