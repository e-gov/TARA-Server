(function() {
    var timeout = 5000;

    try {
        var value = document.body.getAttribute("data-check-form-refresh-rate");
        var number = new Number(value);

        if (number >= 100) {
            timeout = number;
        }
    } catch (e) {}

    setTimeout(function() {
        document.forms['authenticationCheckForm'].submit();
    }, timeout);
})();
