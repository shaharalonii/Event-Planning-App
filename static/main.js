function confirmDelete(eventId) {
  if (confirm("Are you sure you want to delete this event?")) {
      // Send an AJAX request to delete the event
      fetch(`/events/${eventId}`, {
          method: 'DELETE'
      })
      .then(response => response.json())
      .then(data => {
          // Handle the response data as needed
          console.log(data.message);
          // Reload the page or update the event list dynamically
          location.reload();
      })
      .catch(error => {
          console.error('Error:', error);
      });
  }
}


function flashMessage(message, category) {
  // Display flash message using Bootstrap's alert
  const flashContainer = document.getElementById('flash-messages');
  const alertDiv = document.createElement('div');
  alertDiv.classList.add('alert', `alert-${category}`, 'alert-dismissible', 'fade', 'show');
  alertDiv.setAttribute('role', 'alert');
  alertDiv.textContent = message;
  const closeButton = document.createElement('button');
  closeButton.classList.add('btn-close');
  closeButton.setAttribute('type', 'button');
  closeButton.setAttribute('data-bs-dismiss', 'alert');
  alertDiv.appendChild(closeButton);
  flashContainer.appendChild(alertDiv);
}
