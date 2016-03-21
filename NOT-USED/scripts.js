
	//// Première tentative pour le toggle des rôles. Plus nécessaire.
	$( ".button-actions-title" ).click( function( e ) {
		var $this    = $( this )
		    blockIds = $this.attr( "aria-controls" );

		e.preventDefault();

		blockIds = "#" + blockIds.replace( /^\s+|\s+$/g, "" ).replace( /\s+/g, ", #" );

		$( blockIds ).toggle( 250 );

		// It's open: close it.
		if ( $this.attr( "aria-expanded" ) === "true" ) {
			$this.attr( "aria-expanded", "false" );
		}
		// It's closed: open it.
		else {
			$this.attr( "aria-expanded", "true" );
		}
	} );

(function($){

	$( document ).ready( function() {

		$('#password_strength_pattern').prop( 'disabled', false );

		$('#module_active').click( function(e){
			var val = ! $('#block-advanced_options:visible').length;
			$('#block-advanced_options').slideToggle(250);
		} );

		$( ".button-actions-title" ).click( function( e ) {
			var $this = $( this );

			e.preventDefault();

			$( "." + $this.attr( "aria-controls" ) ).toggle( 250 );

			// It's open: close it.
			if ( $this.attr( "aria-expanded" ) === "true" ) {
				$this.attr( "aria-expanded", "false" );
			}
			// It's closed: open it.
			else {
				$this.attr( "aria-expanded", "true" );
			}
		} );

		$('input[data-realtype="password"]').focus(
			function() {
				$(this).attr('type', 'text');
			} );

		$('input[data-realtype="password"]').blur(
			function () {
				$(this).attr('type', 'password');
			}
		);
		if (typeof document.createElement( 'input' ).checkValidity == 'function') {
			var checkboxes = $('fieldset[class*="_affected_role"] :checkbox');
			checkboxes.click( function() {
				$(this).get(0).setCustomValidity( '' );
				if ( checkboxes.filter(':checked').length === 0 ) {
					$(this).get(0).setCustomValidity( l10nmodules.selectOneRoleMinimum );
					$('#main_submit').click();
				}
			});
		} else {
			$('fieldset[class*="_affected_role"].fieldtype-helper_warning p.warning').show();
		}

		var last_block_target = new Array();
		function secupressToggleBlockVisibility( e, t, first ) {
			if ( first ) {
				e.preventDefault();
			}
			var block_val = $(t).val();
			var block_name = $(t).attr('name');
			var block_target = $('.block-' + $(t).val() );
			var block_id = $(t).attr('aria-controls');

			// if ( first || $(t).attr('type') == 'radio' &&  last_block_target[ $(t).attr('name') ] != $( '[name="' + $(t).attr('name') + '"]:checked' ).val() ) {
			if ( $(t).attr('type') == 'radio' ) {
				$('.block-hidden.' + block_id).hide();
			}

			$('.block-hidden.block-' + last_block_target[ $(t).attr('name') ] + ' input').each( function(i,v){
					if ( true != $(v).data('nocheck') ) {
						var pattern = $(v).data('pattern');
						if ( pattern != undefined && pattern != '' ) {
							$(v).removeAttr('pattern');
						}
						var required = $(v).data('required');
						if ( required != undefined && required != '' ) {
							$(v).removeProp('required');
						}
						var aria_required = $(v).data('aria-required');
						if ( aria_required != undefined && aria_required != '' ) {
							$(v).removeAttr('aria-required');
						}
					}
			});

			if ( block_target.length > 0 ) {

				$('.block-hidden.block-' + $(t).val() + ' input').each( function(i,v){
					if ( true != $(v).data('nocheck') ) {
						var pattern = $(v).data('pattern');
						if ( pattern != undefined && pattern != '' ) {
							$(v).attr('pattern', pattern);
						}
						var required = $(v).data('required');
						if ( required != undefined && required != '' ) {
							$(v).prop('required', required);
						}
						var aria_required = $(v).data('aria-required');
						if ( aria_required != undefined && aria_required != '' ) {
							$(v).attr('aria-required', aria_required);
						}
					} else {
						$('.block-hidden.block-' + $(t).val() + ' .new-password').show();
					}
				});

				if( $(t).is(':radio') ) {
					$(block_target).show(tempo);
				} else {
					if ( ( first && ! $(t).prop( 'checked' ) ) || $(t).prop( 'checked' ) ) {
						$(block_target).show(tempo);
					} else {
						if ( ! first ) {
							var not = '';
							$('[name="'+block_name+'"]:checked').each(function(){
								not += '.block-'+$(this).val()+','
							});
							$(block_target).filter(':not('+not+'0)').hide(tempo);
						}
					}
				}
				last_block_target[ $(t).attr('name') ] = $(t).val();
			}
		}

		var tempo = 0;
		$('select[name^="secupress"]').change( function(e){ secupressToggleBlockVisibility( e, $(this), tempo==0 ) } ).change();
		$('input[name^="secupress"]:radio,input[name^="secupress"]:checkbox').click( function(e){
			secupressToggleBlockVisibility( e, $(this), tempo==0 );
		} ).filter(':checked:not(#module_active)').click();
		tempo = 250;

	    function checkPasswordStrength() {
			var pass = $('#double_auth_password').val();

			var strengthResult = $('#password-strength');

			// Reset the form & meter
			strengthResult.removeClass( 'short bad good strong' );
			if ( ! pass ) {
				$('#password-strength').html( pwsL10n.empty ); //// change default
				return;
			}
			// Get the password strength
			var strength = wp.passwordStrength.meter( pass, wp.passwordStrength.userInputBlacklist(), pass );
			$('#password_strength_pattern').val( strength );

			// Add the strength meter results
			switch ( strength ) {

				case 2:
				strengthResult.addClass( 'bad' ).html( pwsL10n.bad );
				break;

				case 3:
				strengthResult.addClass( 'good' ).html( pwsL10n.good );
				break;

				case 4:
				strengthResult.addClass( 'strong' ).html( pwsL10n.strong );
				break;

				case 5:
				strengthResult.addClass( 'short' ).html( pwsL10n.mismatch );
				break;

				default:
				strengthResult.addClass( 'short' ).html( pwsL10n.short );
			}
		}

	    $( '#double_auth_password' ).on( 'input propertychange',
	        checkPasswordStrength
		);

		checkPasswordStrength();

	} );

})(jQuery);

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


// Action/404 Logs =================================================================================
(function($, d, w, undefined) {

	if ( ! w.l10nLogs ) {
		return;
	}

	// Delete all logs.
	function secupressDeleteAllLogs( $button, href ) {
		secupressDisableAjaxButton( $button, w.l10nLogs.clearingText );

		$.getJSON( href )
		.done( function( r ) {
			if ( $.isPlainObject( r ) && r.success ) {
				swal.close();
				// Empty the list and add a "No Logs" text.
				$button.closest( "td" ).text( "" ).append( "<p><em>" + w.l10nLogs.noLogsText + "</em></p>" );

				secupressEnableAjaxButton( $button, w.l10nLogs.clearedText );
			} else {
				secupressDisplayAjaxError( $button, w.l10nLogs.clearImpossible );
			}
		} )
		.fail( function() {
			secupressDisplayAjaxError( $button );
		} );
	}

	// Delete one log.
	function secupressDeleteLog( $button, href ) {
		secupressDisableAjaxButton( $button, w.l10nLogs.deletingText );

		$.getJSON( href )
		.done( function( r ) {
			if ( $.isPlainObject( r ) && r.success ) {
				swal.close();
				// r.data contains the number of logs.
				if ( r.data ) {
					$( ".logs-count" ).text( r.data );

					$button.closest( "li" ).css( "backgroundColor", SecuPress.deletedRowColor ).hide( "normal", function() {
						$( this ).remove();
						SecuPress.doingAjax.global = false;
					} );
				} else {
					// Empty the list and add a "No Logs" text.
					$button.closest( "td" ).text( "" ).append( "<p><em>" + w.l10nLogs.noLogsText + "</em></p>" );
					SecuPress.doingAjax.global = false;
				}

				if ( wp.a11y && wp.a11y.speak ) {
					wp.a11y.speak( w.l10nLogs.deletedText );
				}
			} else {
				secupressDisplayAjaxError( $button, w.l10nLogs.deleteImpossible );
			}
		} )
		.fail( function() {
			secupressDisplayAjaxError( $button );
		} );
	}

	// Ajax call that clears logs.
	$( ".secupress-clear-logs" ).on( "click keyup", function( e ) {
		var $this = $( this ),
			href  = secupressPreAjaxCall( $this.attr( "href" ), e );

		if ( ! href ) {
			return false;
		}

		if ( "function" === typeof w.swal ) {
			swal(
				$.extend( {}, SecuPress.confirmSwalDefaults, {
					text:              w.l10nLogs.clearConfirmText,
					confirmButtonText: w.l10nLogs.clearConfirmButton
				} ),
				function () {
					secupressDeleteAllLogs( $this, href );
				}
			);
		} else if ( w.confirm( w.l10nmodules.confirmTitle + "\n" + w.l10nLogs.clearConfirmText ) ) {
			secupressDeleteAllLogs( $this, href );
		}
	} ).attr( "role", "button" ).removeAttr( "aria-disabled" );

	// Ajax call that delete a log.
	$( ".secupress-delete-log" ).on( "click keyup", function( e ) {
		var $this = $( this ),
			href  = secupressPreAjaxCall( $this.attr( "href" ), e );

		if ( ! href ) {
			return false;
		}

		if ( "function" === typeof w.swal ) {
			swal(
				$.extend( {}, SecuPress.confirmSwalDefaults, {
					text:              w.l10nLogs.deleteConfirmText,
					confirmButtonText: w.l10nLogs.deleteConfirmButton
				} ),
				function () {
					secupressDeleteLog( $this, href );
				}
			);
		} else if ( w.confirm( w.l10nmodules.confirmTitle + "\n" + w.l10nLogs.deleteConfirmText ) ) {
			secupressDeleteLog( $this, href );
		}
	} ).attr( "role", "button" ).removeAttr( "aria-disabled" );

	// Expand <pre> tags.
	$( ".secupress-code-chunk" )
		.prepend( '<button type="button" class="no-button secupress-expand-code"><span class="dashicons-before dashicons-visibility" aria-hidden="true"></span><span class="dashicons-before dashicons-hidden" aria-hidden="true"></span><span class="screen-reader-text">' + w.l10nLogs.expandCodeText + '</span></button>' )
		.children( ".secupress-expand-code" )
		.on( "click", function() {
			$( this ).parent().toggleClass( "secupress-code-chunk" );
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





					/*if ( r.success && $.isPlainObject( r.data ) ) {
						r.data.manualFix = ( r.data.class === "bad" );

						if ( r.data.class !== "error" ) {
							// Deal with the fix infos.
							secupressDisplayFixResult( r, test );
						}

						if ( r.data.class === "error" ) {
							// Retry swal.
							data.swalType = "error";
							data.swalInfo = '<div class="sa-error-container show"><div class="icon">!</div><p>' + r.data.info + '</p></div>';
							secupressManualFixit( test, data );
						} else if ( r.data.class === "warning" ) {
							// Failed.
							swal( {
								title: SecuPressi18nScanner.notFixed,
								text: r.data.info,
								type: "error"
							} );
							secupressDisplayManualFixMsg( $row );
						} else if ( r.data.class === "bad" ) {
							// Success, but it needs another manual fix. Well, it could also mean that the fix failed.
							swal( {
								title: SecuPressi18nScanner.fixedPartial,
								text: r.data.info,
								type: "warning"
							} );
						} else {
							// Success.
							swal( {
								title: SecuPressi18nScanner.fixed,
								text: r.data.info,
								type: "success"
							} );
						}

						// Trigger an event.
						$( "body" ).trigger( "manualFixDone.secupress", [ {
							test: test,
							manualFix: ( r.data.class === "bad" ),
							data: r.data
						} ] );
					} else {
						secupressDisplayFixError( $row );

						// Failed.
						swal( {
							title: SecuPressi18nScanner.notFixed,
							type: "error"
						} );
					}*/

