(function () {
  var stage = document.getElementById('revealStage');
  var layer = document.getElementById('revealLayer');
  if (!stage || !layer) return;

  function setPosition(clientX, clientY) {
    var rect = stage.getBoundingClientRect();
    var x = ((clientX - rect.left) / rect.width) * 100;
    var y = ((clientY - rect.top) / rect.height) * 100;
    layer.style.setProperty('--mx', x + '%');
    layer.style.setProperty('--my', y + '%');
  }

  stage.addEventListener('mousemove', function (e) {
    stage.classList.add('active');
    setPosition(e.clientX, e.clientY);
  });
  stage.addEventListener('mouseleave', function () {
    stage.classList.remove('active');
  });
  stage.addEventListener('touchmove', function (e) {
    if (e.touches.length) {
      stage.classList.add('active');
      setPosition(e.touches[0].clientX, e.touches[0].clientY);
    }
  }, { passive: true });
  stage.addEventListener('touchend', function () {
    stage.classList.remove('active');
  });
})();
