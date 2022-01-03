(function($, d, w, undefined) {

	var captcha_session,
		doing_ajax = false,
		flag       = 0, // 0 = nothing, 1 = ok, -1 = ko, 2 = -1 + return to start
		numImgs    = 9;

		// Shorthand to tell if a modifier key is pressed.
	function secupressHasModifierKey( e ) {
		return e.altKey || e.ctrlKey || e.metaKey || e.shiftKey;
	}
	// Shorthand to tell if the pressed key is Space or Enter.
	function secupressIsSpaceOrEnterKey( e ) {
		return ( e.which === 13 || e.which === 32 ) && ! secupressHasModifierKey( e );
	}

	function secupress_sleep( millis ) {
		var date    = new Date(),
			curDate = null;

		do {
			curDate = new Date();
		}
		while( curDate-date < millis );
	}

	function secupress_captcha_do_fail() {
		$( "span.checkme" ).css( "background-position", "28px 0px" );
		$( "#captcha_token" ).val( "" );
		$( "#msg" ).show();
	}

	function secupress_set_flag_ok() {
		numImgs = 20;
		flag    = 1;
	}

	function secupress_set_captcha_timeout() {
		captcha_session = setTimeout( secupress_captcha_do_fail, 1000 * 59 * 2 ); // ~2 mn
	}

	function secupress_clear_captcha_timeout() {
		clearTimeout( captcha_session );
	}

	$( ".checkme" ).on( "click keyup", function( e ) {
		var animation,
			imgHeight  = 28,
			cont       = 1,
			inc        = 1,
			bgposx     = 0,
			bgposy     = 0,
			ajaxurlsep = w.spCaptchaL10n.ajaxurl.indexOf( "?" ) !== -1 ? "&" : "?";

		if ( doing_ajax || 0 !== flag ) {
			return;
		}

		if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
			return false;
		}

		animation = setInterval( function() {
			// Switch ajax state.
			switch ( flag ) {
				case 1:  bgposx = -28; break;
				case -1: bgposx = 28; break;
				case 0:  bgposx = 0; break;
			}

			// Position of the css checkbox.
			bgposy = - ( cont * imgHeight );
			$( "span.checkme" ).css( "background-position", bgposx + "px " + bgposy + "px" );

			// If animation returned to start.
			if ( cont === 0 ) {
				inc = 1;
				if ( flag === 2 ) {
					clearInterval( animation );
				}
			}

			// If animation hits the end.
			if ( cont === numImgs ) {
				switch( flag ) {
					case 0:
						inc = -1;
						break;
					case 1:
						clearInterval( animation );
						break;
					case -1:
						secupress_sleep( 2000 );
						flag = 2;
						inc  = -1;
						break;
				}
			}

			// Inc/Decrement.
			cont = cont + inc;
		}, 50 );

		$( "#msg" ).hide();

		doing_ajax = true;

		$.get( w.spCaptchaL10n.ajaxurl + ajaxurlsep + "action=captcha_check&oldvalue=" + $( "#captcha_key" ).val() )
		.done( function( data ) {
			setTimeout( secupress_set_flag_ok, 2000 );
			$( "#captcha_key" ).val( data.data );
			secupress_clear_captcha_timeout();
			secupress_set_captcha_timeout();
			$( "span.checkme" ).parent().css( "cursor", "default" );
		} )
		.fail( function() {
			flag    = -1;
			numImgs = 21;
			secupress_captcha_do_fail();
		} )
		.always( function( data ) {
			doing_ajax = false;
		} );
	} );

} )(jQuery, document, window);
