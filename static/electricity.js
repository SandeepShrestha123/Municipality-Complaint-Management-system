(function () {
  var dialog = document.getElementById('mapDialog');
  var frame = document.getElementById('mapFrame');
  var latInput = document.getElementById('latitude');
  var lngInput = document.getElementById('longitude');
  var addressInput = document.getElementById('address');
  var pinState = document.getElementById('pinState');
  var pickedText = document.getElementById('pickedText');
  var confirmBtn = document.getElementById('confirmMap');
  var picked = null;

  function fmt(n) { return Number(n).toFixed(5); }

  function setPin(lat, lng) {
    latInput.value = lat;
    lngInput.value = lng;
    pinState.textContent = 'Location selected: ' + fmt(lat) + ', ' + fmt(lng);
    lookupAddress(lat, lng);
  }

  // Fill the address from OpenStreetMap's Nominatim, only if the field is empty.
  function lookupAddress(lat, lng) {
    if (addressInput.value.trim() !== '') return;
    fetch('https://nominatim.openstreetmap.org/reverse?format=jsonv2&zoom=18&lat=' + lat + '&lon=' + lng)
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d && d.display_name && addressInput.value.trim() === '') {
          addressInput.value = d.display_name;
        }
      })
      .catch(function () { /* the citizen can type the address */ });
  }

  // Opening the dialog loads the Flask /map route (the folium map).
  document.getElementById('openMap').addEventListener('click', function () {
    var url = window.MAP_URL;
    if (latInput.value && lngInput.value) {
      url += '?latitude=' + encodeURIComponent(latInput.value) +
             '&longitude=' + encodeURIComponent(lngInput.value);
    }
    frame.src = url;
    picked = null;
    confirmBtn.disabled = true;
    pickedText.textContent = 'Nothing selected yet.';
    dialog.showModal();
  });

  window.addEventListener('message', function (e) {
    if (e.origin !== window.location.origin) return;
    if (e.data && e.data.type === 'location-picked') {
      picked = { lat: e.data.lat, lng: e.data.lng };
      pickedText.textContent = 'Pin at ' + fmt(picked.lat) + ', ' + fmt(picked.lng);
      confirmBtn.disabled = false;
    }
  });

  confirmBtn.addEventListener('click', function () {
    if (picked) setPin(picked.lat, picked.lng);
    dialog.close();
  });
  document.getElementById('cancelMap').addEventListener('click', function () { dialog.close(); });
  dialog.addEventListener('close', function () { frame.removeAttribute('src'); });

  document.getElementById('useMyLocation').addEventListener('click', function () {
    if (!navigator.geolocation) {
      pinState.textContent = 'Your browser cannot share your location. Use the map instead.';
      return;
    }
    pinState.textContent = 'Finding your location...';
    navigator.geolocation.getCurrentPosition(
      function (pos) { setPin(pos.coords.latitude, pos.coords.longitude); },
      function () { pinState.textContent = 'Could not get your location. Use the map instead.'; },
      { enableHighAccuracy: true, timeout: 10000 }
    );
  });
})();
