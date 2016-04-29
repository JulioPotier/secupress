// Global vars =====================================================================================
var SecuPress = {
	doingAjax:           {},
	deletedRowColor:     "#FF9966",
	addedRowColor:       "#CCEEBB",
	confirmSwalDefaults: {
		title:             window.l10nmodules.confirmTitle,
		confirmButtonText: window.l10nmodules.confirmText,
		cancelButtonText:  window.l10nmodules.cancelText,
		type:              "warning",
		showCancelButton:  true,
		closeOnConfirm:    false,
		allowOutsideClick: true
	}
};


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

/**
 * Disable a button that calls an ajax action.
 * - Add a "working" class, so that the spinner can be displayed.
 * - Add a "aria-disabled" attribute.
 * - If it's a link: add a "disabled" attribute. If it's a button or input: add a "disabled" attribute.
 * - Change the button text if a "data-loading-i18n" attribute is present.
 * - Use `wp.a11y.speak` if a text is provided.
 * - Set a `SecuPress.doingAjax` attribute to `true`.
 *
 * @since 1.0
 *
 * @param (object) $button jQuery object of the button.
 * @param (string) speak   Text for `wp.a11y.speak`.
 * @param (string) ajaxID  An identifier used for `SecuPress.doingAjax`. Default: "global".
 */
function secupressDisableAjaxButton( $button, speak, ajaxID ) {
	var text     = $button.attr( "data-loading-i18n" ),
		isButton = $button.get( 0 ).nodeName.toLowerCase(),
		value;

	ajaxID = undefined !== ajaxID ? ajaxID : "global";
	SecuPress.doingAjax[ ajaxID ] = true;
	isButton = "button" === isButton || "input" === isButton;

	if ( undefined !== text && text ) {
		if ( isButton ) {
			value = $button.val();
			if ( undefined !== value && value ) {
				$button.val( text );
			} else {
				$button.text( text );
			}
		} else {
			$button.text( text );
		}

		if ( undefined === speak || ! speak ) {
			speak = text;
		}
	}

	if ( isButton ) {
		$button.addClass( "working" ).attr( { "disabled": "disabled", "aria-disabled": "true" } );
	} else {
		$button.addClass( "disabled working" ).attr( "aria-disabled", "true" );
	}

	if ( wp.a11y && wp.a11y.speak && undefined !== speak && speak ) {
		wp.a11y.speak( speak );
	}
}

/**
 * Enable a button that calls an ajax action.
 * - Remove the "working" class, so that the spinner can be hidden again.
 * - Remove the "aria-disabled" attribute.
 * - If it's a link: remove the "disabled" attribute. If it's a button or input: remove the "disabled" attribute.
 * - Change the button text if a "data-original-i18n" attribute is present.
 * - Use `wp.a11y.speak` if a text is provided.
 * - Set a `SecuPress.doingAjax` attribute to `false`.
 *
 * @since 1.0
 *
 * @param (object) $button jQuery object of the button.
 * @param (string) speak   Text for `wp.a11y.speak`.
 * @param (string) ajaxID  An identifier used for `SecuPress.doingAjax`. Default: "global".
 */
function secupressEnableAjaxButton( $button, speak, ajaxID ) {
	var text, isButton, value;

	if ( undefined !== $button && $button && $button.length ) {
		text     = $button.attr( "data-original-i18n" );
		isButton = $button.get( 0 ).nodeName.toLowerCase();
		isButton = "button" === isButton || "input" === isButton;

		if ( undefined !== text && text ) {
			if ( isButton ) {
				value = $button.val();
				if ( undefined !== value && value ) {
					$button.val( text );
				} else {
					$button.text( text );
				}
			} else {
				$button.text( text );
			}
		}

		if ( isButton ) {
			$button.removeClass( "working" ).removeAttr( "disabled aria-disabled" );
		} else {
			$button.removeClass( "disabled working" ).removeAttr( "aria-disabled" );
		}
	}

	if ( wp.a11y && wp.a11y.speak && undefined !== speak && speak ) {
		wp.a11y.speak( speak );
	}

	ajaxID = undefined !== ajaxID ? ajaxID : "global";
	SecuPress.doingAjax[ ajaxID ] = false;
}

/**
 * Before doing an ajax call, do some tests:
 * - test if we have an URL.
 * - if the event is "keyup", test if the key is the Space bar or Enter.
 * - test another ajax call is not running.
 * Also prevent default event.
 *
 * @since 1.0
 *
 * @param (string) href The URL.
 * @param (object) e    The jQuery event object.
 * @param (string) ajaxID  An identifier used for `SecuPress.doingAjax`. Default: "global".
 *
 * @return (bool|string) False on failure, the ajax URL on success.
 */
function secupressPreAjaxCall( href, e, ajaxID ) {
	if ( undefined === href || ! href ) {
		return false;
	}

	if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
		return false;
	}

	ajaxID = undefined !== ajaxID ? ajaxID : "global";

	if ( typeof SecuPress.doingAjax[ ajaxID ] === "undefined" ) {
		SecuPress.doingAjax[ ajaxID ] = false;
	}

	if ( SecuPress.doingAjax[ ajaxID ] ) {
		return false;
	}

	e.preventDefault();

	return href.replace( "admin-post.php", "admin-ajax.php" );
}

/**
 * Display an error message via Sweet Alert and re-enable the button.
 *
 * @since 1.0
 *
 * @param (object) $button jQuery object of the button.
 * @param (string) text    Text for swal + `wp.a11y.speak`.
 * @param (string) ajaxID  An identifier used for `SecuPress.doingAjax`. Default: "global".
 */
function secupressDisplayAjaxError( $button, text, ajaxID ) {
	if ( undefined === text ) {
		text = window.l10nmodules.unknownError;
	}

	swal( {
		title:             window.l10nmodules.error,
		confirmButtonText: window.l10nmodules.confirmText,
		html:              text,
		type:              "error",
		allowOutsideClick: true
	} );

	ajaxID = undefined !== ajaxID ? ajaxID : "global";
	secupressEnableAjaxButton( $button, text, ajaxID );
}

/**
 * Display a success message via Sweet Alert and re-enable the button.
 *
 * @since 1.0
 *
 * @param (object) $button jQuery object of the button.
 * @param (string) text    Text for swal + `wp.a11y.speak`.
 * @param (string) ajaxID  An identifier used for `SecuPress.doingAjax`. Default: "global".
 */
function secupressDisplayAjaxSuccess( $button, text, ajaxID ) {
	if ( undefined === text ) {
		text = null;
	}

	swal( {
		title:             window.l10nmodules.done,
		confirmButtonText: window.l10nmodules.confirmText,
		html:              text,
		type:              "success",
		allowOutsideClick: true,
		timer:             4000
	} );

	ajaxID = undefined !== ajaxID ? ajaxID : "global";
	secupressEnableAjaxButton( $button, text, ajaxID );
}


// Roles: at least one role must be chosen. ========================================================
(function($, d, w, undefined) {

	if ( "function" === typeof document.createElement( "input" ).checkValidity ) {
		$( ".affected-role-row :checkbox" ).on( "click", function() {
			this.setCustomValidity( '' );

			if ( 0 === $( '[name="' + this.name + '"]:checked' ).length ) {
				this.setCustomValidity( w.l10nmodules.selectOneRoleMinimum );
				$( "#secupress-module-form-settings [type='submit']" ).first().trigger( "click" );
			}
		} );
	} else {
		$( ".affected-role-row p.warning" ).removeClass( "hide-if-js" );
	}

} )(jQuery, document, window);


// Radioboxes: 1 checked at most. ==================================================================
(function($, d, w, undefined) {

	$( ".radiobox" ).on( "click", function() {
		$( '[name="' + this.name + '"]:checked' ).not( this ).removeAttr( "checked" ).trigger( "change" );
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


// Backups =========================================================================================
(function($, d, w, undefined) {

	if ( ! w.l10nmodules ) {
		return;
	}

	function secupressUpdateAvailableBackupCounter( r ) {
		$( "#secupress-available-backups" ).text( r.data.countText );
	}

	function secupressUpdateBackupVisibility() {
		if ( 0 === $( "#form-delete-db-backups" ).find( ".secupress-large-row" ).length ) {
			$( "#form-delete-db-backups" ).hide();
			$( "#secupress-no-db-backups" ).show();
		} else {
			$( "#secupress-no-db-backups" ).hide();
			$( "#form-delete-db-backups" ).show();
		}
	}

	// Delete all backups.
	function secupressDeleteAllBackups( $button, href ) {
		secupressDisableAjaxButton( $button, w.l10nmodules.deletingAllText, "backup" );

		$.getJSON( href )
		.done( function( r ) {
			if ( $.isPlainObject( r ) && r.success ) {
				swal.close();
				$button.closest( "form" ).find( "fieldset" ).text( "" );

				secupressUpdateBackupVisibility();
				secupressEnableAjaxButton( $button, w.l10nmodules.deletedAllText, "backup" );
			} else {
				secupressDisplayAjaxError( $button, w.l10nmodules.deleteAllImpossible, "backup" );
			}
		} )
		.fail( function() {
			secupressDisplayAjaxError( $button, null, "backup" );
		} );
	}

	// Delete a backup.
	function secupressDeleteOneBackup( $button, href ) {
		secupressDisableAjaxButton( $button, w.l10nmodules.deletingOneText, "backup" );

		$.getJSON( href )
		.done( function( r ) {
			if ( $.isPlainObject( r ) && r.success ) {
				swal.close();

				$button.closest( ".secupress-large-row" ).css( "backgroundColor", SecuPress.deletedRowColor ).hide( "normal", function() {
					$( this ).remove();

					secupressUpdateAvailableBackupCounter( r );
					secupressUpdateBackupVisibility();
					SecuPress.doingAjax.backup = false;
				} );

				if ( wp.a11y && wp.a11y.speak ) {
					wp.a11y.speak( w.l10nmodules.deletedOneText );
				}
			} else {
				secupressDisplayAjaxError( $button, w.l10nmodules.deleteOneImpossible, "backup" );
			}
		} )
		.fail( function() {
			secupressDisplayAjaxError( $button, null, "backup" );
		} );
	}

	// Do a DB backup.
	function secupressDoDbBackup( $button, href ) {
		secupressDisableAjaxButton( $button, w.l10nmodules.backupingText, "backup" );

		$.post( href )
		.done( function( r ) {
			if ( $.isPlainObject( r ) && r.success ) {
				$( r.data.elemRow ).addClass( "hidden" ).css( "backgroundColor", SecuPress.addedRowColor ).prependTo( "#form-delete-db-backups fieldset" ).show( "normal", function() {
					$( this ).css( "backgroundColor", "" );
				} );

				secupressUpdateAvailableBackupCounter( r );
				secupressUpdateBackupVisibility();
				secupressEnableAjaxButton( $button, w.l10nmodules.backupedText, "backup" );
			} else {
				secupressDisplayAjaxError( $button, w.l10nmodules.backupImpossible, "backup" );
			}
		} )
		.fail( function() {
			secupressDisplayAjaxError( $button, null, "backup" );
		} );
	}

	// Ajax call that delete all backups.
	$( "#submit-delete-db-backups" ).on( "click keyup", function( e ) {
		var $this = $( this ),
			href  = secupressPreAjaxCall( $this.closest( "form" ).attr( "action" ), e );

		if ( ! href ) {
			return false;
		}

		if ( "function" === typeof w.swal ) {
			swal( $.extend( {}, SecuPress.confirmSwalDefaults, {
				text:              w.l10nmodules.confirmDeleteBackups,
				confirmButtonText: w.l10nmodules.yesDeleteAll,
				type:              "question"
			} ) ).then( function ( isConfirm ) {
				if ( isConfirm ) {
					swal.enableLoading();
					secupressDeleteAllBackups( $this, href );
				}
			} );
		} else if ( w.confirm( w.l10nmodules.confirmTitle + "\n" + w.l10nmodules.confirmDeleteBackups ) ) {
			secupressDeleteAllBackups( $this, href );
		}

	} ).removeAttr( "disabled aria-disabled" );


	// Ajax call that delete one Backup.
	$( "body" ).on( "click keyup", ".a-delete-backup", function( e ) {
		var $this = $( this ),
			href  = secupressPreAjaxCall( $this.attr( "href" ), e );

		if ( ! href ) {
			return false;
		}

		if ( "function" === typeof w.swal ) {
			swal( $.extend( {}, SecuPress.confirmSwalDefaults, {
				text:              w.l10nmodules.confirmDeleteBackup,
				confirmButtonText: w.l10nmodules.yesDeleteOne,
				type:              "question"
			} ) ).then( function ( isConfirm ) {
				if ( isConfirm ) {
					swal.enableLoading();
					secupressDeleteOneBackup( $this, href );
				}
			} );
		} else if ( w.confirm( w.l10nmodules.confirmTitle + "\n" + w.l10nmodules.confirmDeleteBackup ) ) {
			secupressDeleteOneBackup( $this, href );
		}
	} );

	// Ajax call that do a Backup.
	$( "#submit-backup-db" ).on( "click", function( e ) {
		var $this = $( this ),
			href  = secupressPreAjaxCall( $this.closest( "form" ).attr( "action" ), e );

		if ( ! href ) {
			return false;
		}

		secupressDoDbBackup( $this, href );
	} ).removeAttr( "disabled aria-disabled" );

} )(jQuery, document, window);


// Countries =======================================================================================
(function($, d, w, undefined) {

	function secupress_set_indeterminate_state( code ) {
		var all_boxes     = $( "[data-code-country='" + code + "']" ).length,
			checked_boxes = $( "[data-code-country='" + code + "']:checked" ).length;

		if ( checked_boxes === all_boxes ) {
			$( "[value='continent-" + code + "']" ).prop( { "checked": true, "indeterminate": false } ).css( "-webkit-appearance", "none" );
		} else if ( checked_boxes === 0 ) {
			$( "[value='continent-" + code + "']" ).prop( { "checked": false, "indeterminate": false } ).css( "-webkit-appearance", "none" );
		} else {
			$( "[value='continent-" + code + "']" ).prop( { "checked": false, "indeterminate": true } ).css( "-webkit-appearance", "checkbox" );
		}
	}

	$( ".continent input" ).on( "click", function( e ) {
		var $this = $( this ),
			val   = $this.css( "-webkit-appearance", "none" ).val().replace( "continent-", "" );

		$( ".depends-geoip-system_type_blacklist.depends-geoip-system_type_whitelist [data-code-country='" + val + "']" ).prop( "checked", $this.is( ":checked" ) );
	} );

	$( "[data-code-country]" ).on( "click", function( e ) {
		var code = $( this ).data( "code-country" );
		secupress_set_indeterminate_state( code );
	} );

	$( ".continent input" ).each( function( i ) {
		var code = $( this ).val().replace( "continent-", "" );
		secupress_set_indeterminate_state( code );
	} );

	$( ".expand_country" ).on( "click", function( e ) {
		$( this ).next( "fieldset" ).toggleClass( "hide-if-js" );
	} );

} )(jQuery, document, window);


// Banned IPs ======================================================================================
(function($, d, w, undefined) {

	var $row = $( "#banned-ips-row" ),
		$banForm, banUrl;

	if ( ! $row.length ) {
		return;
	}

	// Fill in the list.
	function secupressBannedIPsFillList( data, replace ) {
		var $list    = $row.find( "#secupress-banned-ips-list" ),
			template = '<li class="secupress-large-row"><strong>%ip%</strong> <em>(%time%)</em><span><a class="a-unban-ip" href="%unban_url%">' + w.l10nmodules.delete + '</a> <span class="spinner secupress-inline-spinner"></span></span></li>',
			isSearch = ! $( "#reset-banned-ips-list" ).hasClass( "hidden" ),
			out      = "";

		if ( undefined === replace || replace ) {
			// We will replace the list content.
			replace = true;
			$list.html( "" );
		}

		if ( undefined === data || ! data.length ) {
			// No data.
			if ( replace ) {
				// We must display a placeholder with a message.
				if ( typeof replace === "string" ) {
					secupressBannedIPsEmptyList( replace );
				} else if ( isSearch ) {
					secupressBannedIPsEmptyList( w.l10nmodules.IPnotFound, false );
				} else {
					secupressBannedIPsEmptyList();
				}
			}
			return;
		}

		// Build the rows html.
		$.each( data, function( i, v ) {
			out += template.replace( /%ip%/g, v.ip ).replace( /%time%/g, v.time ).replace( /%unban_url%/g, v.unban_url );
		} );

		// Insert the rows.
		$list.append( out );
	}

	// Empty the list, display a message in a placeholder (a row in the list), and maybe hide the search form and the "Clear all IPs" button.
	function secupressBannedIPsEmptyList( message, resetSearch ) {
		var $form;

		if ( undefined === message || ! message ) {
			message = w.l10nmodules.noBannedIPs;
		}
		// Remove all rows from the list and display the placeholder.
		$row.find( "#secupress-banned-ips-list" ).html( '<li id="no-ips">' + message + "</li>" );

		if ( undefined !== resetSearch && ! resetSearch ) {
			return;
		}
		// Hide the "Clear all IPs" button and spinner.
		$row.find( "#secupress-clear-ips-button" ).next().addBack().addClass( "hidden" );
		// Hide and reset the search form.
		$form = $row.find( "#form-search-ip" ).addClass( "hidden" );
		// Reset the form.
		$form.find( "#reset-banned-ips-list" ).next().addBack().addClass( "hidden" );
		$form.find( "#secupress-search-banned-ip" ).val( "" );
	}

	// Swal that displays the form to ban an IP address.
	function secupressBanIPswal( $button, href ) {
		swal( $.extend( {}, SecuPress.confirmSwalDefaults, {
			title:             $banForm.find( '[for="secupress-ban-ip"]' ).text(),
			confirmButtonText: $button.data( "original-i18n" ),
			html:              $banForm,
			type:              "info"
		} ) ).then( function ( isConfirm ) {
			if ( isConfirm ) {
				swal.enableLoading();
				secupressBanIP( $button, href );
			}
		} );
	}

	// Perform an ajax call to ban an IP address.
	function secupressBanIP( $button, href ) {
		var params = { "ip": $( "#secupress-ban-ip" ).val() };

		if ( ! params.ip ) {
			secupressBanIPswal( $button, href );
			return;
		}

		secupressDisableAjaxButton( $button, null, "ban-ip" );

		$.getJSON( href, params )
		.done( function( r ) {
			var message;

			if ( ! $.isPlainObject( r ) || ! r.data || ! $.isPlainObject( r.data ) ) {
				secupressDisplayAjaxError( $button, w.l10nmodules.error, "ban-ip" );
				return;
			}

			if ( ! r.success ) {
				message = r.data.message ? r.data.message : null;
				secupressDisplayAjaxError( $button, message, "ban-ip" );
				return;
			}

			// Remove the placeholder if it exists.
			$row.find( "#secupress-banned-ips-list" ).children( "#no-ips" ).remove();

			// Add a new row in the list.
			secupressBannedIPsFillList( r.data.tmplValues, false );

			// Display the search form.
			$row.find( "#form-search-ip" ).removeClass( "hidden" );

			// Display the "Clear all IPs" button.
			$row.find( "#secupress-clear-ips-button" ).next().addBack().removeClass( "hidden" );

			secupressDisplayAjaxSuccess( $button, r.data.message, "ban-ip" );
		} )
		.fail( function() {
			secupressDisplayAjaxError( $button, null, "ban-ip" );
		} );
	}

	// Reset buttons on page load.
	$row.find( "button" ).removeAttr( "disabled aria-disabled" );

	// The form to ban an IP address.
	$banForm = $row.find( "#form-ban-ip" ).remove();
	banUrl   = $banForm.attr( "action" );
	$banForm = $banForm.children().wrapAll( "<div id='secupress-ban-ip-fields' />" ).parent();
	$banForm.find( "[type='submit']" ).remove();

	// Search an IP address.
	$row.on( "submit", "#form-search-ip", function( e ) {
		var $this  = $( this ),
			$field = $this.find( "#secupress-search-banned-ip" ),
			href   = secupressPreAjaxCall( d.location.href, e, "ban-ip" ),
			ip     = $field.val(),
			$button, params;

		if ( ! href || ! ip ) {
			return;
		}

		$button = $field.next();
		params  = $this.serializeArray();

		secupressDisableAjaxButton( $button, null, "ban-ip" );

		$row.load( href + " #banned-ips-row > th, #banned-ips-row > td", params, function() {
			$row.find( "#form-ban-ip" ).remove();
			$row.find( "#secupress-search-banned-ip" ).focus();
			secupressEnableAjaxButton( $row.find( "#secupress-search-banned-ip" ), w.l10nmodules.searchResults, "ban-ip" );
		} );
	} );

	// Reset search.
	$row.on( "click keyup", "#reset-banned-ips-list", function( e ) {
		var $this = $( this ),
			href  = secupressPreAjaxCall( d.location.href, e, "ban-ip" );

		if ( ! href ) {
			return;
		}

		secupressDisableAjaxButton( $this, null, "ban-ip" );

		$row.load( href + " #banned-ips-row > th, #banned-ips-row > td", function() {
			$row.find( "#form-ban-ip" ).remove();
			$row.find( "#secupress-search-banned-ip" ).focus();
			secupressEnableAjaxButton( $this, w.l10nmodules.searchReset, "ban-ip" );
		} );
	} );

	// Ban an IP address.
	$row.on( "click keyup", "#secupress-ban-ip-button", function( e ) {
		var $this = $( this ),
			href  = secupressPreAjaxCall( banUrl, e, "ban-ip" );

		if ( href ) {
			secupressBanIPswal( $this, href );
		}
	} );

	// Unban an IP address.
	$row.on( "click keyup", ".a-unban-ip", function( e ) {
		var $this = $( this ),
			href  = secupressPreAjaxCall( $this.attr( "href" ), e, "ban-ip" );

		if ( ! href ) {
			return;
		}

		secupressDisableAjaxButton( $this, null, "ban-ip" );

		$.getJSON( href )
		.done( function( r ) {
			var $list, $li, message;

			if ( ! $.isPlainObject( r ) || ! r.data || ! $.isPlainObject( r.data ) ) {
				secupressDisplayAjaxError( $this, w.l10nmodules.error, "ban-ip" );
				return;
			}

			if ( ! r.success ) {
				message = r.data.message ? r.data.message : null;
				secupressDisplayAjaxError( $this, message, "ban-ip" );
				return;
			}

			// Remove the row from the list.
			$li   = $this.closest( ".secupress-large-row" );
			$list = $li.parent();
			$li.remove();

			// The list is empty.
			if ( ! $list.children().length ) {
				if ( $( "#reset-banned-ips-list" ).hasClass( "hidden" ) ) {
					// It's not a search.
					secupressBannedIPsEmptyList();
				} else {
					// It's a search.
					secupressBannedIPsEmptyList( w.l10nmodules.IPremoved, false );
				}
			}

			secupressDisplayAjaxSuccess( $this, r.data.message, "ban-ip" );
		} )
		.fail( function() {
			secupressDisplayAjaxError( $this, null, "ban-ip" );
		} );
	} );

	// Unban all IP addresses.
	$row.on( "click keyup", "#secupress-clear-ips-button", function( e ) {
		var $this = $( this ),
			href  = secupressPreAjaxCall( $this.attr( "href" ), e, "ban-ip" );

		if ( ! href ) {
			return;
		}

		secupressDisableAjaxButton( $this, null, "ban-ip" );

		$.getJSON( href )
		.done( function( r ) {
			var $list = $this.siblings( "#secupress-banned-ips-list" ),
				message;

			if ( ! $.isPlainObject( r ) || ! r.data || ! $.isPlainObject( r.data ) ) {
				secupressDisplayAjaxError( $this, w.l10nmodules.error, "ban-ip" );
				return;
			}

			if ( ! r.success ) {
				message = r.data.message ? r.data.message : null;
				secupressDisplayAjaxError( $this, message, "ban-ip" );
				return;
			}

			// Remove all rows from the list, display the placeholder, etc.
			secupressBannedIPsEmptyList();

			secupressDisplayAjaxSuccess( $this, r.data.message, "ban-ip" );
		} )
		.fail( function() {
			secupressDisplayAjaxError( $this, null, "ban-ip" );
		} );
	} );

} )(jQuery, document, window);
