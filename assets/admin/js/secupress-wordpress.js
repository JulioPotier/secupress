/* globals jQuery: false, ajaxurl: false, SecuPressi18n: false, swal2: false */
// !Global vars ====================================================================================
var SecuPress = {
	swal2Defaults:        {
		confirmButtonText: SecuPressi18n.confirmText,
		cancelButtonText:  SecuPressi18n.cancelText,
		type:              "warning",
		allowOutsideClick: true,
		customClass:       "wpmedia-swal2 secupress-swal2"
	},
	swal2ConfirmDefaults: {
		showCancelButton: true,
		closeOnConfirm:   false
	}
};
/**
 * Basic tools
 */
// Shorthand to tell if a modifier key is pressed.
function secupressHasModifierKey( e ) {
	return e.altKey || e.ctrlKey || e.metaKey || e.shiftKey;
}
// Shorthand to tell if the pressed key is Space or Enter.
function secupressIsSpaceOrEnterKey( e ) {
	return ( e.which === 13 || e.which === 32 ) && ! secupressHasModifierKey( e );
}
// Shorthand to tell if the pressed key is Space.
function secupressIsSpaceKey( e ) {
	return e.which === 32 && ! secupressHasModifierKey( e );
}
// Shorthand to tell if the pressed key is Enter.
function secupressIsEnterKey( e ) {
	return e.which === 13 && ! secupressHasModifierKey( e );
}
// Shorthand to tell if the pressed key is Escape.
function secupressIsEscapeKey( e ) {
	return e.which === 27 && ! secupressHasModifierKey( e );
}

jQuery( document ).ready( function( $ ) {

	// Themes page: Move the "div alert" when a theme is vulnerable. ===============================
	(function($, d, w, undefined) {

		$( ".secupress-bad-theme" ).each( function( index, html ) {
			var $theme = $( "*[data-slug='" + $( this ).attr( "data-theme" ) + "']" );
			$theme.find( ".theme-actions .activate, .theme-actions .load-customize" ).remove();
			if ( $theme.find( ".update-message" ).length > 0 ) {
				$(html).css('top', '40px');
			}
			$theme.find( ".theme-screenshot" ).after( html );
		} );

	} )(jQuery, document, window);

} );
