// Tools ===========================================================================================
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

// Password ========================================================================================
(function($, d, w, undefined) {

	$( "#double-auth_password" ).on( "input pwupdate init.secupress", function() { //// Comparer avec le code qu'utilise actuellement WP.
		var pass, strengthResult, strength;

		pass = this.value;

		strengthResult = $( "#password-strength" ).removeClass( "short bad good strong" );

		if ( ! pass ) {
			return;
		}

		// Get the password strength
		strength = wp.passwordStrength.meter( pass, wp.passwordStrength.userInputBlacklist(), pass );

		$( "#password_strength_pattern" ).val( strength );

		// Add the strength meter results
		switch ( strength ) {
			case 2:
				strengthResult.addClass( "bad" ).html( w.pwsL10n.bad );
				break;
			case 3:
				strengthResult.addClass( "good" ).html( w.pwsL10n.good );
				break;
			case 4:
				strengthResult.addClass( "strong" ).html( w.pwsL10n.strong );
				break;
			case 5:
				strengthResult.addClass( "short" ).html( w.pwsL10n.mismatch );
				break;
			default:
				strengthResult.addClass( "short" ).html( w.pwsL10n.short );
		}
	} ).trigger( "init.secupress" ); //// Dans ton ancien code c'était "input propertyChange". WP semble utiliser ça maintenant. A regarder de près donc.


	$( "#password_strength_pattern" ).prop( "disabled", false )
		.closest( "tr" )
		// Triggered before the panel is opened: add pattern/required/aria-required attributes.
		.on( "secupressbeforeshow", function() {
			var $this   = $( this ),
				$inputs = $this.find( "input" ),
				pattern, required, ariaRequired;

			$inputs.each( function(){
				var $this = $( this );

				if ( "true" === $this.data( "nocheck" ) ) {
					$this.find( ".new-password" ).show();
					return true;
				}

				pattern = $this.data( "pattern" );

				if ( undefined !== pattern && "" !== pattern ) {
					$this.attr( "pattern", pattern );
				}

				required = $this.data( "required" );

				if ( undefined !== required && "" !== required ) {
					$this.attr( "required", required );
				}

				ariaRequired = $this.data( "aria-required" );

				if ( undefined !== ariaRequired && "" !== ariaRequired ) {
					$this.attr( "aria-required", ariaRequired );
				}
			} );
		} )
		// Triggered before the panel is closed: remove pattern/required/aria-required attributes.
		.on( "secupressbeforehide", function() {
			var $this   = $( this ),
				$inputs = $this.find( "input" ),
				pattern, required, ariaRequired;

			$inputs.each( function(){
				var $this = $( this );

				if ( "true" === $this.data( "nocheck" ) ) {
					return true;
				}

				pattern = $this.data( "pattern" );

				if ( undefined !== pattern && "" !== pattern ) {
					$this.removeAttr( "pattern" );
				}

				required = $this.data( "required" );

				if ( undefined !== required && "" !== required ) {
					$this.removeAttr( "required" );
				}

				ariaRequired = $this.data( "aria-required" );

				if ( undefined !== ariaRequired && "" !== ariaRequired ) {
					$this.removeAttr( "aria-required" );
				}
			} );
		} );

} )(jQuery, document, window);


// Roles: at least one role must be chosen. ========================================================
(function($, d, w, undefined) {
	var checkboxes;

	if ( "function" === typeof document.createElement( "input" ).checkValidity ) {
		checkboxes = $( 'fieldset[class*="_affected_role"] :checkbox' );

		checkboxes.on( "click", function() {
			$( this ).get( 0 ).setCustomValidity( '' );

			if ( 0 === checkboxes.filter( ":checked" ).length ) {
				$( this ).get( 0 ).setCustomValidity( w.l10nmodules.selectOneRoleMinimum );
				$( "#secupress-module-form-settings [type='submit']" ).first().trigger( "click" );
			}
		} );
	} else {
		$( 'fieldset[class*="_affected_role"]' ).siblings( "p.warning" ).removeClass( "hide-if-js" );
	}

} )(jQuery, document, window);


// Radiobox class ==================================================================================
(function($, d, w, undefined) {
	$( ".radiobox" ).on( "click", function() {
		var $this = $( this ),
			name  = $this.attr( "name" );
		$( '.radiobox[name="' + name + '"]:checked' ).not( $this ).removeAttr( "checked" ).trigger( "change" );
	} );
} )(jQuery, document, window);


// Show/Hide panels, depending on some other field value. ==========================================
(function($, d, w, undefined) {

	var $depends   = $( "#wpbody-content" ).find( '[class*="depends-"]' ), // Rows that will open/close.
		dependsIds = {}, // IDs of the checkboxes, radios, etc that will trigger a panel open/close.
		dependsRadioNames = {}; // names of the radios.

	$depends.each( function() {
		var classes = $( this ).attr( "class" ).replace( /^\s+|\s+$/g, "" ).replace( /\s+/, " " ).split( " " );

		$.each( classes, function( i, id ) {
			var $input,        // input element
				inputTagName,  // input tag name
				inputTypeAttr, // input type
				inputNameAttr, // input name
				inputIsValid = false;

			// If the class is not a "depends-XXXXXX", bail out.
			if ( 0 !== id.indexOf( "depends-" ) ) {
				return true;
			}

			id = id.substr( 8 );

			// If the ID was previously delt with, bail out.
			if ( "undefined" !== typeof dependsIds[ id ] ) {
				return true;
			}
			dependsIds[ id ] = 1;

			$input = $( "#" + id );

			// Uh? The input doesn't exist?
			if ( ! $input.length ) {
				return true;
			}

			// We need to know which type of input we deal with, the way we deal with it is not the same.
			inputTagName = $input.get( 0 ).nodeName.toLowerCase();

			if ( "input" === inputTagName ) {
				inputTypeAttr = $input.attr( "type" ).toLowerCase();

				if ( "checkbox" === inputTypeAttr || "radio" === inputTypeAttr ) {
					inputIsValid = true;
				}

			} else if ( "button" === inputTagName ) {
				inputIsValid = true;
			}

			// Only checkboxes, radios groups and buttons so far.
			if ( ! inputIsValid ) {
				return true;
			}

			// Attach the events.
			// Buttons
			if ( "button" === inputTagName ) {

				$input.on( "click", function() {
					var id = $( this ).attr( "id" );
					$( ".depends-" + id ).toggle( 250 );
				} );

			}
			// Radios
			else if ( "radio" === inputTypeAttr ) {

				inputNameAttr = $input.attr( "name" );

				// If the name was previously delt with, bail out.
				if ( "undefined" !== typeof dependsRadioNames[ inputNameAttr ] ) {
					return true;
				}
				dependsRadioNames[ inputNameAttr ] = 1;

				$( '[name="' + inputNameAttr + '"]' ).on( "change init.secupress", function( e ) {
					var $this   = $( this ),
						$toShow = $( ".depends-" + $this.attr( "id" ) ), // Elements to show.
						toHide  = [], // Elements to hide.
						tempo   = "init" === e.type && "secupress" === e.namespace ? 0 : 250; // On page load, no animation.

					// The radio is checked: open the desired boxes if not visible.
					$toShow.not( ":visible" ).trigger( "secupressbeforeshow" ).show( tempo, function() {
						$( this ).trigger( "secupressaftershow" );
					} );

					// Find boxes to hide.
					$( '[name="' + $this.attr( "name" ) + '"]' ).not( $this ).each( function() {
						toHide.push( ".depends-" + $( this ).attr( "id" ).replace( /^\s+|\s+$/g, "" ) );
					} );

					$( toHide.join( "," ) ).not( $toShow ).filter( ":visible" ).trigger( "secupressbeforehide" ).hide( tempo, function() {
						$( this ).trigger( "secupressafterhide" );
					} );
				} ).filter( ":checked" ).trigger( "init.secupress" );

			}
			// Checkboxes
			else if ( "checkbox" === inputTypeAttr ) {

				$input.on( "change init.secupress", function( e ) {
					var $this  = $( this ),
						id     = $this.attr( "id" ),
						$elems = $( ".depends-" + id ), // Elements to hide or show.
						tempo  = "init" === e.type && "secupress" === e.namespace ? 0 : 250; // On page load, no animation.

					// Uh? No rows?
					if ( ! $elems.length ) {
						return true;
					}

					// The checkbox is checked: open if not visible.
					if ( $this.is( ":checked" ) ) {
						$elems.not( ":visible" ).trigger( "secupressbeforeshow" ).show( tempo, function() {
							$( this ).trigger( "secupressaftershow" );
						} );
					}
					// The checkbox is not checked: close if visible and no other checkboxes that want this row to be open is checked.
					else {
						$elems.filter( ":visible" ).each( function() {
							var $this   = $( this ),
								classes = $this.attr( "class" ).replace( /^\s+|\s+$/g, "" ).replace( /\s+/, " " ).split( " " ),
								others  = []; // Other checkboxes

							$.each( classes, function( i, v ) {
								if ( "depends-" + id !== v && 0 === v.indexOf( "depends-" ) ) {
									others.push( "#" + v.substr( 8 ) + ":checked" );
								}
							} );

							others = others.join( "," );

							if ( ! $( others ).length ) {
								$this.trigger( "secupressbeforehide" ).hide( tempo, function() {
									$( this ).trigger( "secupressafterhide" );
								} );
							}
						} );
					}
				} ).filter( ":checked" ).trigger( "init.secupress" );

			}
		} );
	} );

} )(jQuery, document, window);


// Action Logs =====================================================================================
(function($, d, w, undefined) {

	function secupressActionLogsDisplayError( $this ) {
		var $parent = $this.closest( "td" );

		$parent.children( ".error-message" ).remove();
		$parent.append( "<p class=\"error-message\"><em>" + w.l10nAlogs.errorText + "</em></p>" );

		if ( wp.a11y && wp.a11y.speak ) {
			wp.a11y.speak( w.l10nAlogs.errorText );
		}

		$this.removeClass( "disabled" ).removeAttr( "aria-disabled" );
	}

	// Ajax call that clears logs.
	$( ".secupress-clear-logs" ).on( "click keyup", function( e ) {
		var $this = $( this ),
			href  = $this.attr( "href" );

		if ( undefined === href || ! href ) {
			return false;
		}

		if ( e.type === "keyup" && ! secupressIsSpaceOrEnterKey( e ) ) {
			return false;
		}

		if ( $this.hasClass( "disabled" ) ) {
			return false;
		}

		if ( ! w.confirm( w.l10nAlogs.clearConfirmText ) ) {
			return false;
		}

		$this.addClass( "disabled" ).attr( "aria-disabled", "true" );
		e.preventDefault();

		if ( wp.a11y && wp.a11y.speak ) {
			wp.a11y.speak( w.l10nAlogs.clearingText );
		}

		$.post( href.replace( "admin-post.php", "admin-ajax.php" ) )
		.done( function( r ) {
			if ( "1" === r ) {
				$this.closest( "td" ).text( "" ).append( "<p><em>" + w.l10nAlogs.noLogsText + "</em></p>" );

				if ( wp.a11y && wp.a11y.speak ) {
					wp.a11y.speak( w.l10nAlogs.clearedText );
				}
			} else {
				secupressActionLogsDisplayError( $this );
			}
		} )
		.fail( function() {
			secupressActionLogsDisplayError( $this );
		} );
	} );

} )(jQuery, document, window);


// Countries =======================================================================================
(function($, d, w, undefined) {

	$( ".geoip-system_geoip-countries" ).on( "click", function( e ) {
		var val = $( this ).val();
		$( ".fieldtype-countries" ).find( "[data-code-country='" + val + "']" ).prop( "checked", $( this ).is( ":checked" ) );
	} );

	$( "[data-code-country]" ).on( "click", function( e ) {
		var code = $( this ).data( "code-country" );
		$( "[value='" + code + "']" ).prop( "checked", Boolean( $( "[data-code-country='" + code + "']:checked" ).length == $( "[data-code-country='" + code + "']" ).length ) );
	} );

} )(jQuery, document, window);


// Fixed scroll ====================================================================================
/*(function($, d, w, undefined) {

	var $sidebar   = $( "h2.nav-tab-wrapper" ),
		$window    = $( w ),
		offset     = $sidebar.offset(),
		topPadding = 35;

	$window.scroll( function() {
		if ( $window.scrollTop() > offset.top ) {
			$sidebar.stop().animate( {
				marginTop: $window.scrollTop() - offset.top + topPadding
			}, 250 );
		} else {
			$sidebar.stop().animate( {
				marginTop: 0
			} );
		}
	} );

} )(jQuery, document, window);*/