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


// Show/Hide panels, depending on some other field value. ==========================================
(function($, d, w, undefined) {

	var $depends   = $( "#wpbody-content" ).find( '[class*="depends-"]' ), // Rows that will open/close.
		dependsIds = {}; // IDs of the checkboxes, radios, etc that will trigger a panel open/close.

	$depends.each( function() {
		var classes = $( this ).attr( "class" ).replace( /^\s+|\s+$/g, "" ).replace( /\s+/, " " ).split( " " );

		$.each( classes, function( i, id ) {
			var $target, targetTagName, targetTypeAttr, targetNameAttr, targetIsValid = false;

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

			$target = $( "#" + id );

			// Uh? The input doesn't exist?
			if ( ! $target.length ) {
				return true;
			}

			// We need to know which type of input we deal with, the way we deal with it is not the same.
			targetTagName = $target.get( 0 ).nodeName.toLowerCase();

			if ( "input" === targetTagName ) {
				targetTypeAttr = $target.attr( "type" ).toLowerCase();

				if ( "checkbox" === targetTypeAttr || "radio" === targetTypeAttr ) {
					targetIsValid = true;
				}

			} else if ( /*"select" === targetTagName || */"button" === targetTagName ) {
				targetIsValid = true;
			}

			// Only checkboxes, radios groups and buttons so far.
			if ( ! targetIsValid ) {
				return true;
			}

			// Attach the events.
			// Buttons
			if ( "button" === targetTagName ) {

				$target.on( "click", function() {
					var id = $( this ).attr( "id" );
					$( ".depends-" + id ).toggle( 250 );
				} );

			}
			// Radios
			else if ( "radio" === targetTypeAttr ) {

				// Radios don't trigger a "change" event on uncheck: we need to monitor the entire group.
				targetNameAttr = $target.attr( "name" );

				$( '[name="' + targetNameAttr + '"]' ).on( "change init.secupress", { targetId: id }, function( e ) {
					var id     = $( this ).attr( "id" ),
						$elems = $( ".depends-" + e.data.targetId ),
						tempo  = "init" === e.type && "secupress" === e.namespace ? 0 : 250; // On page load, no animation.

					// Uh? No rows?
					if ( ! $elems.length ) {
						return true;
					}

					// The desired radio is checked: open if not visible.
					if ( e.data.targetId === id ) {
						$elems.not( ":visible" ).trigger( "secupressbeforeshow" ).show( tempo, function() {
							$( this ).trigger( "secupressaftershow" );
						} );
					}
					// Another radio is checked: close if visible.
					else {
						$elems.filter( ":visible" ).trigger( "secupressbeforehide" ).hide( tempo, function() {
							$( this ).trigger( "secupressafterhide" );
						} );
					}
				} ).filter( ":checked" ).trigger( "init.secupress" );

			}
			// Checkboxes
			else if ( "checkbox" === targetTypeAttr ) {

				$target.on( "change init.secupress", function( e ) {
					var $this  = $( this ),
						id     = $this.attr( "id" ),
						$elems = $( ".depends-" + id ),
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

// Countries ======================================================================================

	(function($, d, w, undefined) {
		
		$( ".geoip-system_geoip-countries" ).on( "click", function( e ) {
				var val = $( this ).val();
				$( ".fieldtype-countries" ).find( "[data-code-country='" + val + "']" ).prop( "checked", $( this ).is( ":checked" ) );
			}
		);

		$( "[data-code-country]" ).on( "click", function( e ) {
				var code = $( this ).data( "code-country" );
				$( "[value='" + code + "']" ).prop( "checked", Boolean( $( "[data-code-country='" + code + "']:checked" ).length == $( "[data-code-country='" + code + "']" ).length ) );
			}

		);

	} )(jQuery, document, window);

// Fixed scroll ===================================================================================
$(function() {

    var $sidebar   = $("h2.nav-tab-wrapper"), 
        $window    = $(window),
        offset     = $sidebar.offset(),
        topPadding = 35;

    $window.scroll(function() {
        if ($window.scrollTop() > offset.top) {
            $sidebar.stop().animate({
                marginTop: $window.scrollTop() - offset.top + topPadding
            }, 250);
        } else {
            $sidebar.stop().animate({
                marginTop: 0
            });
        }
    });
    
});

// Radiobox class =================================================================================
$(function() {
//// bug quand on a une des checkbox qui ouvre un panel
    $(".radiobox").on( "click", function(e) { 
    	var id = $( this ).attr( "id" );
    	$( ".radiobox:not(#" + id + "):checked" ).trigger( "click" );
    });
    
});


} )(jQuery, document, window);