from django.db.models.signals import post_save
from django.dispatch import receiver
from app1.models import Invoice, Payment, ServiceRegister, ServiceRequest


@receiver(post_save, sender=Invoice)
def update_service_request_work_status(sender, instance, **kwargs):
    # Check if the payment status is partially paid
    if instance.payment_status == 'partially_paid' and instance.invoice_type == 'service_request':
        try:
            # Get the associated service request
            service_request = instance.service_request
            if service_request:
                # Update the work status to 'in_progress'
                service_request.work_status = 'in_progress'
                service_request.save()
        except ServiceRequest.DoesNotExist:
            # Log or handle the error if service request is not found
            print("ServiceRequest associated with Invoice not found.")

@receiver(post_save, sender=Invoice)
def activate_service_after_full_payment(sender, instance, **kwargs):
    # Check if the payment status is fully paid
    if instance.payment_status == 'paid' and instance.invoice_type == 'service_registration':
        try:
            # Retrieve the related service registration
            service_register = instance.service_register

            # Check if the service_register exists and has a service_provider
            if service_register is not None and service_register.service_provider is not None:
                # Update the status of the registered service to active
                service_register.status = 'active'
                service_register.save()
                print(f"ServiceRegister {service_register.id} has been activated due to full payment.")
            else:
                # Log an error if the service_register or service_provider is missing
                print("Error: ServiceRegister or ServiceProvider not found for this Invoice.")
                
        except AttributeError as e:
            # Handle the case where an attribute is missing
            print(f"Error: {e}")


@receiver(post_save, sender=Invoice)
def update_lead_balance_on_payment(sender, instance, **kwargs):
    # Check if payment status is updated to "paid"
    if instance.payment_status == "paid" and instance.invoice_type == 'lead_purchase':
        # Fetch the related ServiceRegister instance
        service_register = instance.service_register
        
        # Calculate and add the leads to the available lead balance
        lead_quantity = instance.quantity * service_register.subcategory.collar.lead_quantity
        service_register.available_lead_balance += lead_quantity
        
        # Save the updated ServiceRegister instance
        service_register.save()         

            