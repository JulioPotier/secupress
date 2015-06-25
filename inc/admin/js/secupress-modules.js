(function($){

	$( document ).ready( function() {

		$('#password_strength_pattern').prop( 'disabled', false );

		$('#module_active').click( function(e){
			var val = ! $('#block-advanced_options:visible').length;
			$('#block-advanced_options').slideToggle(250);
			if ( val ) {
				$('#main_submit').hide();
			} else {
				$('#main_submit').show();
			}
		} );

		$('.button-actions-title').click( function(e){
			e.preventDefault();
			var block_id = $(this).attr('for');
			$('.block-'+block_id).toggle( 250 );
			if ( 'none' != $(this).find('.dashicons-arrow-right').css( 'transform' ) ) {
				$(this).css( 'opacity', '' ).find('.dashicons-arrow-right').css( {'transform': 'none','-ms-transform': 'none','-webkit-transform': 'none',} );
			} else {
				$(this).css( 'opacity', '1' ).find('.dashicons-arrow-right').css( {'transform': 'rotate(90deg)','-ms-transform': 'rotate(90deg)','-webkit-transform': 'rotate(90deg)',} );
			}
		});

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

		var last_block_target = null;
		function secupressToggleBlockVisibility( t ) {
			console.log('ok');
			var block_target = $('.block-' + $(t).val() );
			var block_id = $(t).attr('for');
			$('.block-hidden.block-' + block_id).hide();
			// console.log( '...'+$(v).data('nocheck') );

			$('.block-hidden.block-' + last_block_target + ' input').each( function(i,v){
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
					// } else {
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
						console.log( $('.block-hidden.block-' + $(t).val() + ' .new-password').length );
						$('.block-hidden.block-' + $(t).val() + ' .new-password').show();
					}
				});
				$(block_target).show(tempo);
				last_block_target = $(t).val();
			}
		}

		var tempo = 0;
		$('select[name^="secupress"]').change( function(){ secupressToggleBlockVisibility( $(this) ) } ).change();
		$('input[name^="secupress"]:radio').click( function(){ secupressToggleBlockVisibility( $(this) ) } ).filter(':checked').click();
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