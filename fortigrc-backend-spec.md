# FortiGRC: Backend Logic & Database Specification

## 1. Database Schema Specifications (Relational Structure)
The backend requires a relational database setup (PostgreSQL via Supabase) to manage risks, compliance controls, and uploaded evidence. The structure must enforce quantitative risk measurement to align with the Jordanian National Cybersecurity Framework (JNCSF).

### Table: `risks`
* **id**: Unique Identifier (UUID, Primary Key).
* **title**: String.
* **jncsf_capability**: Enumerated type restricting values to the six main JNCSF capabilities ('Architecture & Portfolio', 'Development', 'Delivery', 'Operations', 'Fundamental Capabilities', 'National Cyber Responsibility').
* **event_frequency**: Numeric float representing the annualized rate of occurrence.
* **event_magnitude**: Numeric float representing the financial loss exposure in JOD.
* **quantitative_score**: A generated/computed column that automatically multiplies `event_frequency` by `event_magnitude`.
* **status**: Enumerated type ('Open', 'In Progress', 'Mitigated').
* **created_at**: Timestamp.

### Table: `compliance_controls`
* **id**: Unique Identifier (UUID, Primary Key).
* **risk_id**: Foreign key linking to `risks.id` (with cascade delete).
* **control_name**: String.
* **select_principle**: Enumerated type mapping to the S.E.L.E.C.T principles ('Strategic', 'Enterprise Driven', 'Livable', 'Economical', 'Capability Based', 'Trustable').
* **is_compliant**: Boolean flag.
* **created_at**: Timestamp.

### Table: `evidence_documentation`
* **id**: Unique Identifier (UUID, Primary Key).
* **entity_id**: UUID linking to either a risk or a compliance control.
* **entity_type**: Enumerated type specifying if the attachment belongs to a 'Risk' or 'Compliance' record.
* **file_name**: String (original name of the uploaded file).
* **file_url**: String containing the secure URL from the storage bucket.
* **uploaded_at**: Timestamp.

## 2. Storage Specifications
* A dedicated storage bucket named `fortigrc-evidence` must be configured to handle file uploads (PDFs, images, DOCX).
* Access control policies must be set to ensure only authenticated system users can upload, read, or delete files within this bucket.

## 3. API Endpoint Logic & Workflows

### A. Endpoint: Create New Risk
* **Operation**: POST request accepting risk details.
* **Logic**: 
  1. Validate incoming payload matches the required `risks` schema.
  2. Insert the record into the database. The database engine must handle the automated calculation of the `quantitative_score`.
  3. Return the created risk object, including the computed score.

### B. Endpoint: Create Compliance Control
* **Operation**: POST request accepting compliance details.
* **Logic**:
  1. Validate the `risk_id` exists in the `risks` table.
  2. Validate the incoming principle against the allowed S.E.L.E.C.T values.
  3. Insert the record and return the success status to the frontend.

### C. Endpoint/Utility: File Upload Handler
* **Operation**: Multipart/form-data handler.
* **Logic**:
  1. Receive the file stream from the frontend payload.
  2. Generate a unique filename using a timestamp and the associated entity ID to prevent collisions.
  3. Upload the file directly to the `fortigrc-evidence` storage bucket.
  4. Retrieve the generated public or signed URL from the storage provider.
  5. Execute a database insertion into the `evidence_documentation` table linking the generated URL, the original filename, and the target entity (Risk or Compliance).
  6. Return the file URL to the frontend for UI rendering.

## 4. Reporting & Aggregation Logic
* **Total Quantitative Exposure**: A backend function must aggregate the `quantitative_score` of all risks where the status is NOT 'Mitigated'. This total is required by the frontend to render the economic impact dashboard.
* **Audit Export Preparation**: An aggregation query must be built to fetch a nested JSON structure containing all Risks, their associated Compliance Controls, and their linked Evidence URLs. This structured data payload will feed the PDF generator for external audits.

## 5. Security & Settings Logic
* **Zero Trust Enforcement**: The backend must support session management logic capable of forcing strict timeouts and handling Multi-Factor Authentication (MFA) state validation.
* **Role-Based Access**: Implement middleware to verify user roles before allowing write operations to the risk registry or compliance tables.