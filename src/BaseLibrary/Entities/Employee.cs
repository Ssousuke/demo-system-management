namespace BaseLibrary.Entities
{
    public class Employee
    {
        public Guid Id { get; set; }
        public string? Name { get; set; }
        public string? CivicilId { get; set; }
        public string? FileNumber { get; set; }
        public string? FullName { get; set; }
        public string? JobName { get; set; }
        public string? Address { get; set; }
        public string? TelephoneNumber { get; set; }
        public string? Photo { get; set; }
        public string? Other { get; set; }


        // Relationship: Many to One
        public GeneralDepartment? GeneralDepartment { get; set; }
        public Guid GeneralDepartmentId { get; set; }

        public Department? Department { get; set; }
        public Guid DepartmentId { get; set; }

        public Branch? Branch { get; set; }
        public Guid BranchId { get; set; }

        public Town? Town { get; set; }
        public Guid TownId { get; set; }
    }
}