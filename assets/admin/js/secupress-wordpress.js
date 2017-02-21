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
			var $theme = $( "#" + $( this ).attr( "data-theme" ) + "-name" );
			$theme.parent().find( ".theme-update" ).remove();
			$theme.parent().find( ".theme-actions .activate" ).remove();
			$theme.after( html );
		} );

		/* Everywhere but profile page: The recovery email notice can modify the profile page for the recovery email value */

		// On dismiss, show a swal to alert about the necessity of the recover email address
		$( ".secupress-is-dismissible a[href*='notice_id=recovery_email']" ).on( "click", function( e ) {
			if ( $( "#secupress_recovery_email:visible" ).length ) {
				swal2( $.extend( {}, SecuPress.swal2Defaults, SecuPress.swal2ConfirmDefaults, {
					title:             SecuPressi18n.recoveryEmailNeeded,
					html:              SecuPressi18n.forYourSecurity,
					showConfirmButton: false,
					type:              "warning"
				} ) );
			}
		} );

		// Click on retry will play with visibility only.
		$( "#secupress_recovery_email_parent" ).on( "click", "#secupress_recovery_email_retry", function( e ) {
			$( "#secupress_recovery_email_result" ).text( "" );
			$( "#secupress_recovery_email_retry" ).hide();
			$( "#secupress_recovery_email_submit" ).show();
			$( "#secupress_recovery_email" ).show().focus().select();
		} );

		// Click on submit or hit "enter" inside the input field.
		$( "#secupress_recovery_email_parent" ).on( "click keyup", "#secupress_recovery_email, #secupress_recovery_email_submit", function( e ) {
			var email, $_spin;

			if ( "keyup" === e.type && ! secupressIsEnterKey( e ) ) {
				return;
			}

			if ( "click" === e.type && ( ! e.target || ! e.target.id || "secupress_recovery_email_submit" !== e.target.id ) ) {
				return;
			}

			$( "#secupress_recovery_email_submit" ).hide();
			email  = $( "#secupress_recovery_email" ).hide().val();
			$_spin = $( "#secupress_recovery_email_spinner" ).show();

			$.post( ajaxurl, { secupress_recovery_email: email, action: "secupress_recovery_email" } )
			.always( function( data ) {
				$_spin.hide();
				$( "#secupress_recovery_email_result" ).html( data );
				// 1 char length is the "valid check" emoji, else, show the retry button.
				if ( 1 < data.length ) {
					$( "#secupress_recovery_email_retry" ).show().focus();
				}
			} );
		} );

	} )(jQuery, document, window);

} );
