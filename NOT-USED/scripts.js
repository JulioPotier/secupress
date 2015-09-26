
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