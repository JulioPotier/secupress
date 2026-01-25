// Get the submit from the WP comment form
var dcts_submit = [];
var commentForm = document.getElementById( secupressDctsTimer.cfDefaults.id_form );

if (commentForm !== null && typeof commentForm.querySelectorAll === 'function') {
	dcts_submit = commentForm.querySelectorAll( '#' + secupressDctsTimer.cfDefaults.id_submit );
}
// If there is not, bail.
if ( dcts_submit.length ) {
	// Get the button label
	var dcts_submit_value = dcts_submit[0].value;
	// Set our timer in JS from our filter
	var dcts_timer = secupressDctsTimer.dctsTimer;
	// Disable the button and make it alpha 50%
	dcts_submit[0].setAttribute("disabled", "");
	dcts_submit[0].style.opacity = 0.5;
	// Change the label to include the timer at max value
	dcts_submit[0].value = dcts_submit[0].value + ' (' + dcts_timer + ')';
	// Every second, reduce the timer by 1 and print it in the button
	dcts_submit_interval = setInterval(
		function() {
			dcts_timer--;
			dcts_submit[0].value = dcts_submit_value + ' (' + dcts_timer + ')';
		},
	1000 );
	// When the timer is done, reset the label, alpha, disabled status of the button
		setTimeout(
			function() { 
				clearInterval( dcts_submit_interval );
				var witness = document.getElementById("secupress_dcts_timer_witness");
				if ( witness ) {
					witness.parentNode.removeChild( witness );
				}

				dcts_submit[0].value         = dcts_submit_value;
				dcts_submit[0].style.opacity = 1;
				dcts_submit[0].removeAttribute("disabled");
			},
		dcts_timer * 1000 );

	var gmtOffset       = secupressDctsTimer.gmtOffset;
	var serverTime      = new Date( new Date().getTime() + ( gmtOffset * 3600 * 1000 ) );
	var serverTimestamp = Math.floor( serverTime.getTime() / 1000 );

	document.getElementById("secupress_dcts_timer").value = serverTimestamp;
}