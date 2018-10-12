var API = new API(document.body.getAttribute("data-application-url"));
var APP = new APP();

$("input[id*='personalCode']").keypress(function (event) {
    return APP.isValid(event, APP.isNumber);
});

$("input[id*='mobileNumber']").keyup(function (event) {
    if (!APP.isValid(event, APP.isPhoneNumber, this.value)) {
        if (this.value[0] == "+") {
            this.value = "+" + this.value.replace(/\D/g, '');
        } else {
            this.value = this.value.replace(/\D/g, '');
        }
    }
    return true;
});

$('#accordion').on('hidden.bs.collapse', APP.toggleChevron);
$('#accordion').on('shown.bs.collapse', APP.toggleChevron);

$('#idCardForm button').on('click', function(){
    APP.loginByIDCard();
    return false;
});

$('#mobileIdSubmitButton').on('click', function(){
    $('#mobileIdForm').submit();
});

$('#eIDAScountryList button').on('click', function(){
     $('#eidasForm input[name="country"]').val($(this).find( "div" ).attr('id'));
     $('#eidasForm').submit()
});

$('#bankList button').on('click', function(){
     $('#bankForm input[name="bank"]').val($(this).find( "div" ).attr('id'));
     $('#bankForm').submit()
});

$('#smartIdSubmitButton').on('click', function(){
    $('#smartIdForm').submit();
});
