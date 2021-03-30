var $ = jQuery;
$(document).ready(function(){
    var opener = $('[data-plugin="secupress-pro/secupress-pro.php"] span.deactivate a');
    new ModalSecuPress( $("#secupress-Modal"), opener );
    $('.secupress-Modal-footer .secupress-button').attr('href', $(opener).attr('href') );
    $('.secupress-button-send').hide();

    $('#secupress-send-reason').on( 'click', function(e) {
        var params = {
            action: 'secupress_send_deactivation_info',
            reason: $('#secupress-reason').val()+' '+$('#secupress-details').val(),
            nonce : $('#secupress-Modal').data('nonce')
        };
        $.get( ajaxurl, params );
    });
});


/*-----------------------------------------------*\
    CLASS ModalSecuPress, fork from ModalWpr
\*-----------------------------------------------*/
/**
 * Manages the display of deactivation modal box
 *
 * @since 2.0
 * @changelog improvement: better .opener selector,
              improvement: usage of dashicons instead of custom font,
              improvement: branded header,
              improvement: light animations,
              improvement: possibility to use html in title,
              improvement: better usage of native jQuery,
              fix bug: reclick on radio does not trigger next step,
              fix bug: escape does not close the popup,
              fix bug: click on overlay do not close the popup,
              fix bug: 2 buttons showing up at the same time (do not ask user to make a choice after a choice…),
              fix bug: Cancel link was not align left or center, just weirdly between,
              fix bug: radio is already checked when popup is canceled then reopened or when user hit back on the popup,
 *
 * Public method :
   open - Open the modal
   close - Close the modal
   change - Test if modal state change
 *
 */

function ModalSecuPress(aElem, opener) {

    var refThis        = this;
    this.elem          = aElem;
    this.overlay       = $('.secupress-Modal-overlay');
    this.radio         = $('input[name=reason]', aElem);
    this.closer        = $('.secupress-Modal-close, .secupress-Modal-cancel', aElem);
    this.return        = $('.secupress-Modal-return', aElem);
    this.opener        = opener;
    this.question      = $('.secupress-Modal-question', aElem);
    this.button        = $('.secupress-button-send', aElem);
    this.title         = $('.secupress-Modal-header h2', aElem);
    this.textFields    = $('input[type=text], textarea', aElem);
    this.hiddenReason  = $('#secupress-reason', aElem);
    this.hiddenDetails = $('#secupress-details', aElem);
    this.titleText     = this.title.html();

    // Open
    this.opener.click(function(e) {
        e.preventDefault();
        refThis.open();
    });

    // Close
    this.closer.click(function() {
        refThis.close();
    });

    $('body').on('keyup', function(){
        if(27 === event.keyCode){ // ECHAP
            refThis.close();
        }
    });

    $('.secupress-Modal-overlay').on('click', function(){
          refThis.close();
    });

    // Back
    this.return.click(function() {
        refThis.returnToQuestion();
    });

    // Click on radio
    this.radio.click(function(){
        refThis.change($(this));
    });

    // Write text
    this.textFields.keyup(function() {
        refThis.hiddenDetails.val($(this).val());
        if(refThis.hiddenDetails.val() != ''){
            refThis.button.removeClass('secupress-isDisabled');
            refThis.button.removeAttr("disabled");
        }
        else{
            refThis.button.addClass('secupress-isDisabled');
            refThis.button.attr("disabled", true);
        }
    });
}


/*
* Change modal state
*/
ModalSecuPress.prototype.change = function(aElem) {

    var id      = aElem.attr('id');
    var refThis = this;

    // Reset values
    this.hiddenReason.val(aElem.val());
    this.hiddenDetails.val('');
    this.textFields.val('');

    $('.secupress-Modal-fieldHidden').hide(200);
    $('.secupress-Modal-hidden').hide(200);
    $('.secupress-button-send').show();
    $('.secupress-button-skip').hide();

    switch(id){
      case 'sp-reason-temporary':
          // Nothing to do
      break;

      case 'sp-reason-broke':
      case 'sp-reason-score':
      case 'sp-reason-hacked':
      case 'sp-reason-complicated':
          var $panel = $('#' + id + '-panel');
          refThis.question.hide(200);
          refThis.return.show();
          $panel.show(200);

          var titleText = aElem.next('label').html();
          this.title.html(titleText);
      break;

      case 'sp-reason-competitor':
      case 'sp-reason-other':
          var field = aElem.siblings('.secupress-Modal-fieldHidden');
          field.show(200);
          field.find('input, textarea').focus().keyup();
      break;
    }
};



/*
* Return to the question
*/
ModalSecuPress.prototype.returnToQuestion = function() {

    $('.secupress-Modal-fieldHidden').hide(200);
    $('.secupress-Modal-hidden').hide(200);
    this.question.show(200);
    this.return.hide();
    this.title.html(this.titleText);
    this.radio.prop('checked', false);
    // Reset values
    this.hiddenReason.val('');
    this.hiddenDetails.val('');

    $('.secupress-button-send').hide();
    $('.secupress-button-skip').show();
};


/*
* Open modal
*/
ModalSecuPress.prototype.open = function() {
    var refThis = this;
    this.overlay.fadeIn(100, function(){
      refThis.elem.slideDown(300);
    });
};


/*
* Close modal
*/
ModalSecuPress.prototype.close = function() {

    var refThis = this;
    this.returnToQuestion();
    this.elem.slideUp(200, function(){
      refThis.overlay.fadeOut(80);
    });
    this.radio.prop('checked', false);

};
