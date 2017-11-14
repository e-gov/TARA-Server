function isNumber(event) {
    return !isNaN(String.fromCharCode(event.which));
}

function isPhoneNumber(event, value) {
    if (value.length == 1) {
        return event.which == 171 || isNumber(event)
    } else if (value.length > 1 && value[0] == "+") {
        return value.match(/\+/gi).length < 2 && (event.which == 171 || isNumber(event));
    }
    return isNumber(event);
}

function isValid(event, f, arg1) {
    return $.inArray(event.which, [8, 13]) == 0 || f(event, arg1);
}